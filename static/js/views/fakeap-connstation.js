define(
['jquery','lodash','backbone','semantic','utils/tpl','libs/jquery.tablesort'],

function($, _, Backbone, $, tpl) {
	var FakeApConnStationView = Backbone.View.extend({

		tagName: 'table',

		className: 'ui hover compact sortable table',

		initialize: function(){
			this.template = _.template(tpl.get('fakeap-connstation'));
			this.model.bind("reset",this.render,this);
		},

		render: function(){
			this.$el.html(this.template());
			_.each(this.model.models,function(connstation){
				this.appendList(connstation);
			},this);

			return this;
		},

		sortTable: function(){
			this.$el.tablesort();
		},

		appendList: function(connstation){
			this.$el.find('tbody').append(new FakeApConnStationList({
				model: connstation
			}).render().el);
		}
	});
	
	var FakeApConnStationList = Backbone.View.extend({

		tagName: "tr",

		initialize: function(){
			this.template = _.template(tpl.get('fakeap-connstation-list'));
			this.model.bind("change", this.render,this);
			this.model.bind("destroy",this.close,this);
		},

		render: function(){
			this.$el.html(this.template(this.model.toJSON()));
			return this;
		}

	});
	
	return FakeApConnStationView;


});