define(
['jquery','lodash','backbone'],

function($,_,Backbone) {
	var FakeAp = Backbone.Model.extend({
		urlRoot: "/api/fakeap",
		defaults:{
			"enc" : "",
			"ssid" : "",
			"password" : "",
			"connstation" : null,
			"loginstation" : null
		},

	});

	return FakeAp;

});