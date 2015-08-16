define(
['jquery','lodash','backbone'],

function($,_,Backbone) {
	var Project = Backbone.Model.extend({
		urlRoot: "/api/projects",
		defaults:{
			"id": null,
			"p_name": "",
			"p_desc":"",
			"p_time":""
		}
	});

	return Project;

});