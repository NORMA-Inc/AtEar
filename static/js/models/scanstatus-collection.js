define(
['jquery','lodash','backbone','models/scanstatus-model'],

function($,_,Backbone, ScanStatus) {
	var ScanStatuses = Backbone.Collection.extend({
		
		model: ScanStatus,

		initialize: function(models,options){
			this.id = options.id;
			this.cell = null;
		},

		url: function(){
			if(this.cell==null) {
				return '/api/scanstatus/'+this.id;
			} else {
				return '/api/scanstatus/'+this.id+'/'+this.cell;
			}
		},

		setCellName: function(cell){
			this.cell = cell;
		},

		save: function(){
			Backbone.sync('create',this,{});
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