'use strict';

module.exports = {
  buildSecurityReport: require('./securityReport.js').buildSecurityReport,
  parseUrl: require('./urlParser.js').parseUrl,
  checkImpersonation: require('./impersonationChecker.js').checkImpersonation,
};
