var repoInspectors = require('./inspectors');
var gemfileLockToDependencies = require('./gemfile-lock-to-dependencies');

module.exports = {
  inspect: inspect,
};

function inspect(root, targetFile) {
  return gatherSpecs(root, targetFile)
    .then(function (specs) {
      var pkg = {
        name: specs.packageName,
        targetFile: specs.targetFile,
      };
      var gemfileLockBase64 = specs.files.gemfileLock.contents;
      var gemfileLockContents = Buffer.from(gemfileLockBase64, 'base64').toString();
      console.time('gemfileLockToDependencies');
      pkg.dependencies = gemfileLockToDependencies(gemfileLockContents);
      console.timeEnd('gemfileLockToDependencies');
      return {
        plugin: {
          name: 'bundled:rubygems',
          runtime: 'unknown',
        },
        package: pkg,
      };
    });
}

function gatherSpecs(root, targetFile) {
  for (var i = repoInspectors.length - 1; i >= 0; i--) {
    var inspector = repoInspectors[i];
    if (inspector.canHandle(targetFile)) {
      return inspector.gatherSpecs(root, targetFile);
    }
  }
  throw new Error('Could not handle file: ' + targetFile);
}
