define(
['jquery','lodash','backbone','models/project-model'],

function($,_,Backbone, Project) {
	var Projects = Backbone.Collection.extend({
		model:Project,
		url:"/api/projects"
	});

	return Projects;

});