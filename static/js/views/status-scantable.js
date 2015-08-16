define(
['jquery','lodash','backbone','semantic','utils/tpl','libs/jquery.tablesort'],

function($, _, Backbone, $, tpl) {
	var StatusScanTableView = Backbone.View.extend({

		tagName: 'div',

		className: 'ui raised segment',

		initialize: function(){
			this.template = _.template(tpl.get('status-scantable'));
			this.model.bind("reset",this.render,this);
			this.model.bind("add",this.appendList,this);
		},

		render: function(){
			this.$el.html(this.template());

			_.each(this.model.models,function(scanStatus){
				this.appendList(scanStatus);
			},this);

			this.sortTable();
			return this;
		},

		sortTable: function(){
			this.$el.find('table').tablesort();
		},

		appendList: function(scanStatus){
			this.$el.find('tbody').append(new StatusScanTableListView({
				model: scanStatus
			}).render().el);
		}
	});
	
	var StatusScanTableListView = Backbone.View.extend({

		tagName: "tr",

		initialize: function(){
			this.template = _.template(tpl.get('status-scantable-list'));
			this.model.bind("change", this.render,this);
			this.model.bind("destroy",this.close,this);
		},

		render: function(){
			this.$el.html(this.template(this.model.toJSON()));
			return this;
		}
	})
	return StatusScanTableView;


});