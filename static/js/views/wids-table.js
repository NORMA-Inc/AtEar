define(
['jquery','lodash','backbone','semantic','utils/tpl','libs/jquery.tablesort'],

function($, _, Backbone, $, tpl) {
	var WidsTableView = Backbone.View.extend({

		tagName: 'div',

		className: 'ui raised segments',

		initialize: function(){
			this.template = _.template(tpl.get('wids-table'));
			this.model.bind("reset",this.render,this);
			this.model.bind("add",this.appendList,this);
		},

		render: function(){
			this.$el.html(this.template());

			_.each(this.model.models,function(wids){
				this.appendList(wids);
			},this);

			this.sortTable();
			return this;
		},

		sortTable: function(){
			this.$el.find('table').tablesort();
		},

		appendList: function(wids){
			this.$el.find('tbody').append(new WidsTableListView({
				model: wids
			}).render().el);
		}
	});
	
	var WidsTableListView = Backbone.View.extend({

		tagName: "tr",

		initialize: function(){
			this.template = _.template(tpl.get('wids-table-list'));
			this.model.bind("change", this.render,this);
			this.model.bind("destroy",this.close,this);
		},

		render: function(){
			this.$el.html(this.template(this.model.toJSON()));
			return this;
		}
	})
	return WidsTableView;


});