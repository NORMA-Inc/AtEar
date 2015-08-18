define(
['jquery','lodash','backbone','models/scanstatus-model'],

function($,_,Backbone, ScanStatus) {
	var ScanStatuses = Backbone.Collection.extend({
		
		model: ScanStatus,

		url: function(){
			return '/api/scanstatus';
		},
		
		stop: function(){
			this.cell = null;
			this.reset();
			Backbone.sync('create',this,{});
		},

		distinctKey: function(key){
			return _.compact(_.uniq(this.pluck(key)));
		}

	});

	return ScanStatuses;

});