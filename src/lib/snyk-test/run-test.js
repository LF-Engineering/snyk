module.exports = runTest;

var _ = require('lodash');
var debug = require('debug')('snyk');
var fs = require('then-fs');
var moduleToObject = require('snyk-module');
var pathUtil = require('path');
var depGraphLib = require('snyk-dep-graph');

var analytics = require('../analytics');
var config = require('../config');
var detect = require('../../lib/detect');
var plugins = require('../plugins');
var ModuleInfo = require('../module-info');
var isCI = require('../is-ci');
var request = require('../request');
var snyk = require('../');
var spinner = require('../spinner');
var common = require('./common');

function runTest(packageManager, root, options) {
  return Promise.resolve().then(function () {
    var policyLocations = [options['policy-path'] || root];
    var hasDevDependencies = false;
    var lbl = 'Querying vulnerabilities database...';
    var depGraphRes = {};
    return assemblePayload(root, options, policyLocations, depGraphRes)
      .then(function (res) {
        return spinner(lbl).then(function () {
          return res;
        });
      })
      .then(function (payload) {
        var filesystemPolicy = payload.body && !!payload.body.policy;
        return new Promise(function (resolve, reject) {
          request(payload, function (error, res, body) {
            if (error) {
              return reject(error);
            }

            if (res.statusCode !== 200) {
              var err = new Error(body && body.error ?
                body.error :
                res.statusCode);

              err.userMessage = body && body.userMessage;
              // this is the case where a local module has been tested, but
              // doesn't have any production deps, but we've noted that they
              // have dep deps, so we'll error with a more useful message
              if (res.statusCode === 404 && hasDevDependencies) {
                err.code = 'NOT_FOUND_HAS_DEV_DEPS';
              } else {
                err.code = res.statusCode;
              }

              if (res.statusCode === 500) {
                debug('Server error', body.stack);
              }

              return reject(err);
            }

            body.filesystemPolicy = filesystemPolicy;

            resolve(body);
          });
        });
      }).then(function (res) {

        const legacyRes = {};

        // TODO: remove me
        var nodeFs = require('fs');
        nodeFs.writeFileSync('/tmp/test-graph-result.json', JSON.stringify(res));

        const result = res.result;

        legacyRes.dependencyCount = depGraphRes.depGraph.getPkgs().length - 1;

        // TODO: make sure the way you handle null versions is the same here and in vuln
        let upgradePathsMap = [];
        Object.keys(result.affectedDeps).forEach(function (depId) {
          const issues = result.affectedDeps[depId].issues;
          Object.keys(issues).forEach(function (issueId) {
            if (issues[issueId].fixInfo) {
              issues[issueId].fixInfo.upgradePaths.forEach(function (upgradePath) {
                const key = getIssueWithVulnPathStr(
                  issueId,
                  upgradePath.path.map(toPkgId));
                //TODO: check if key already exists in upgradePathsMap?
                upgradePathsMap[key] = toLegacyUpgradePath(upgradePath.path);
              });
            }
          });
        });

        legacyRes.vulnerabilities = [];
        Object.keys(result.affectedDeps).forEach(function (depId) {
          const dep = result.affectedDeps[depId].dep;
          const depIssues = result.affectedDeps[depId].issues;
          const vulnPaths = depGraphRes.depGraph.pkgPathsToRoot(dep);
          vulnPaths.forEach(function (vulnPath) {
            Object.keys(depIssues).forEach(function (issueId) {
              const vulnPathNonGraphFormat = getVulnPathNonGraphFormat(vulnPath);
              const key = getIssueWithVulnPathStr(issueId, vulnPathNonGraphFormat);
              let partialIssue = _.pick(result.issues[issueId],
                [
                  'id',
                  'type',
                  'title',
                  'packageName',
                  'moduleName', // still used?
                  'semver',
                  'severity',
                  'name',
                  'info',
                ]
              );
              const upgradePath = upgradePathsMap[key];
              partialIssue.upgradePath = upgradePath;
              partialIssue.from = vulnPathNonGraphFormat;
              partialIssue.isUpgradable = !upgradePath ? false : (!!upgradePath[0] || !!upgradePath[1]);
              partialIssue.isPatchable = depIssues[issueId].fixInfo.isPatchable, // TODO: test this
              partialIssue.name = dep.name;
              partialIssue.version = dep.version;
              legacyRes.vulnerabilities.push(partialIssue);
            });
          });
        });

        const meta = res.meta || {};
        legacyRes.org = meta.org;
        legacyRes.policy = meta.policy;
        legacyRes.isPrivate = !meta.isPublic;

        analytics.add('vulns-pre-policy', legacyRes.vulnerabilities.length);
        return Promise.resolve()
          .then(function () {
            if (options['ignore-policy']) {
              return legacyRes;
            }

            return snyk.policy.loadFromText(legacyRes.policy)
              .then(function (policy) {
                return policy.filter(legacyRes, root);
              });
          })
          .then(function (legacyRes) {
            analytics.add('vulns', legacyRes.vulnerabilities.length);

            // add the unique count of vulnerabilities found
            legacyRes.uniqueCount = 0;
            var seen = {};
            legacyRes.uniqueCount = legacyRes.vulnerabilities.reduce(function (acc, curr) {
              if (!seen[curr.id]) {
                seen[curr.id] = true;
                acc++;
              }
              return acc;
            }, 0);

            return legacyRes;
          });
      })
      // clear spinner in case of success or failure
      .then(spinner.clear(lbl))
      .catch(function (error) {
        spinner.clear(lbl)();
        throw error;
      });
  });

  function getIssueWithVulnPathStr(issueId, vulnPath) {
    const issueWithVulnPath = {
      issueId,
      vulnPath,
    };
    return JSON.stringify(issueWithVulnPath);
  }

  // TODO: rename
  function getVulnPathNonGraphFormat(vulnPath) {
    return vulnPath.slice().reverse().map(function (pkg) {
      return toPkgId(pkg);
    });
  }

  function toLegacyUpgradePath(upgradePath) {
    return upgradePath
      .filter((item) => !item.isDropped)
      .map((item) => {
        if (!item.newVersion) {
          return false;
        }

        return `${item.name}@${item.newVersion}`;
      });
  }

  function toPkgId(pkg) {
    return `${pkg.name}@${pkg.version || null}`;
  }
}

function assemblePayload(root, options, policyLocations, depGraphRes) {
  var local;
  if (options.docker) {
    local = true;
    policyLocations = policyLocations.filter(function (loc) {
      return loc !== root;
    });
  } else {
    local = fs.existsSync(root);
  }
  analytics.add('local', local);
  return local ? assembleLocalPayload(root, options, policyLocations, depGraphRes)
    : assembleRemotePayload(root, options);
}

function assembleLocalPayload(root, options, policyLocations, depGraphRes) {
  options.file = options.file || detect.detectPackageFile(root);
  var plugin = plugins.loadPlugin(options.packageManager, options);
  var moduleInfo = ModuleInfo(plugin, options.policy);
  var analysisType = options.docker ? 'docker' : options.packageManager;
  var lbl = 'Analyzing ' + analysisType + ' dependencies for ' +
    pathUtil.relative('.', pathUtil.join(root, options.file || ''));

  var depGraph;
  return spinner(lbl)
    .then(function () {
      return moduleInfo.inspect(root, options.file, options);
    })
    // clear spinner in case of success or failure
    .then(spinner.clear(lbl))
    .catch(function (error) {
      spinner.clear(lbl)();
      throw error;
    })
    .then(async function (info) {
      var pkg = info.package;
      if (_.get(info, 'plugin.packageManager')) {
        options.packageManager = info.plugin.packageManager;
      }
      if (!_.get(pkg, 'docker.baseImage') && options['base-image']) {
        pkg.docker = pkg.docker || {};
        pkg.docker.baseImage = options['base-image'];
      }
      // TODO: handle ruby

      depGraph = await depGraphLib.legacy.depTreeToGraph(info.package, options.packageManager);

      fs.writeFileSync('/tmp/test-dep-graph.json', JSON.stringify(depGraph.toJSON(), null, 2));

      depGraphRes.depGraph = depGraph;
      analytics.add('policies', policyLocations.length);
      analytics.add('packageManager', options.packageManager);
      analytics.add('packageName', depGraph.rootPkg.name);
      analytics.add('packageVersion', depGraph.rootPkg.version);
      analytics.add('package', depGraph.rootPkg.name + '@' + depGraph.rootPkg.version);

      if (policyLocations.length === 0) {
        return Promise.resolve(null);
      }
      return snyk.policy.load(policyLocations, options);
    }).catch(function (error) { // note: inline catch, to handle error from .load
      // the .snyk file wasn't found, which is fine, so we'll return the payload
      if (error.code === 'ENOENT') {
        return null;
      }
      throw error;
    }).then(function (policy) {
      var requestParams = {
        method: 'POST',
        url: config.API + '/test-dep-graph',
        json: true,
        headers: {
          'x-is-ci': isCI,
          authorization: 'token ' + snyk.api,
        },
        qs: common.assembleQueryString(options),
        body: {
          depGraph: depGraph.toJSON(),
          policy: policy && policy.toString(),
          module: {
            name: depGraph.rootPkg.name,
            version: depGraph.rootPkg.version,
            // TODO: target file
          },
          isDocker: !!options.docker,
        },
      };

      return requestParams;
    });
}

function assembleRemotePayload(root, options) {
  var pkg = moduleToObject(root);
  var encodedName = encodeURIComponent(pkg.name + '@' + pkg.version);
  debug('testing remote: %s', pkg.name + '@' + pkg.version);
  analytics.add('packageName', pkg.name);
  analytics.add('packageVersion', pkg.version);
  analytics.add('packageManager', options.packageManager);
  analytics.add('package', pkg.name + '@' + pkg.version);
  var payload = {
    method: 'GET',
    url: vulnUrl(options.packageManager) + '/' + encodedName,
    json: true,
    headers: {
      'x-is-ci': isCI,
      authorization: 'token ' + snyk.api,
    },
  };
  payload.qs = common.assembleQueryString(options);
  return Promise.resolve(payload);
}

function vulnUrl(packageManager) {
  return config.API + '/vuln/' + packageManager;
}
