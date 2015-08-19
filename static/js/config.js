// Original concepts provided by Backbone Boilerplate project: https://github.com/tbranyen/backbone-boilerplate
require.config({
  // Initialize the application with the main application file
  deps: ["main"],

  baseUrl: "static/js",

  paths: {
    // Libraries
    'jquery': "libs/jquery",
    'lodash': "libs/lodash.min",
    'backbone': "libs/backbone.min",
    'semantic': "libs/semantic.min"
  },

  shim: {
    'jqeury': {
      exports: '$'
    },
    'lodash': {
      exports: '_'
    },
    'backbone': {
      deps: ['jquery','lodash'],
      exports: "Backbone"
    },
    'semantic': {
      deps: ['jquery'],
      exports: '$'
    }
  }
});
