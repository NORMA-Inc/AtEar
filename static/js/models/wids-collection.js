define(
['jquery','lodash','backbone','models/wids-model'],

function($,_,Backbone, Wids) {
	var WidsList = Backbone.Collection.extend({
		
		model: Wids,
		url: '/api/wids'

	});

	return WidsList;

});