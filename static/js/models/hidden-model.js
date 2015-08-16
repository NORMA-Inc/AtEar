define(
['jquery','lodash','backbone'],

function($,_,Backbone) {
	var HiddenModel = Backbone.Model.extend({

		defaults:{
			"message": []
		},

		url: function(){
			return '/api/hidden/'+this.widsOption;
		},

		initialize: function(){
			var savedWidsOption = localStorage.getItem('wids');
			if( savedWidsOption == null) {
				this.widsOption = 0;
				localStorage.setItem('wids',0);
			} else {
				this.widsOption  = savedWidsOption;
			}
		},

		setWidsOption: function(signal){
			this.widsOption = signal;
			localStorage.setItem('wids',signal);
		},

		messageLength: function(){
			return this.toJSON().message.length;
		},

		messageToCollection: function(){
			var collection = new Backbone.Collection(this.toJSON().message);
			return collection;
		},

		stringToArray: function(){
			this.set("message",JSON.parse(this.get("message")));
		}

	});

	return HiddenModel;

});