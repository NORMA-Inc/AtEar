define(
['jquery','lodash','backbone'],

function($,_,Backbone) {
	var ScanStatus = Backbone.Model.extend({
		"idAttribute": "bssid",
		
		defaults:{
			enc: 'N/A'
		}
	});

	return ScanStatus;

});