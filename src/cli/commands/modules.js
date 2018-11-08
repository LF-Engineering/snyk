var detect = require('../../lib/detect');
var plugins = require('../../lib/plugins');
var ModuleInfo = require('../../lib/module-info');

module.exports = function (path, options) {
  if (!options) {
    options = {};
  }

  var targetFile = detect.detectPackageFile(path);
  var packageManager = detect.detectPackageManager(path, options);
  var plugin = plugins.loadPlugin(packageManager, options);
  var moduleInfo = ModuleInfo(plugin, options.policy);

  return moduleInfo.inspect(path, targetFile, options).then(function (modules) {
    if (options.json) {
      return JSON.stringify(modules, '', 2);
    }

    return Object.keys(modules.package.dependencies).map(function (key) {
      return modules.package.dependencies[key].name + '@' + modules.package.dependencies[key].version;
    }).join('\n');
  });
};
