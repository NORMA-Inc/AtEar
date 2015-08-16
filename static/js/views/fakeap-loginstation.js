define(
['jquery','lodash','backbone','semantic','utils/tpl','libs/jquery.tablesort'],

function($, _, Backbone, $, tpl) {
	var FakeApLoginStationView = Backbone.View.extend({

		tagName: 'table',

		className: 'ui hover compact sortable table',

		initialize: function(){
			this.template = _.template(tpl.get('fakeap-loginstation'));
			this.model.bind("reset",this.render,this);
		},

		render: function(){
			this.$el.html(this.template());
			_.each(this.model.models,function(loginstation){
				this.appendList(loginstation);
			},this);

			return this;
		},

		sortTable: function(){
			this.$el.tablesort();
		},

		appendList: function(loginstation){
			this.$el.find('tbody').append(new FakeApLoginStationList({
				model: loginstation
			}).render().el);
		}
	});
	
	var FakeApLoginStationList = Backbone.View.extend({

		tagName: "tr",

		initialize: function(){
			this.template = _.template(tpl.get('fakeap-loginstation-list'));
			this.model.bind("change", this.render,this);
			this.model.bind("destroy",this.close,this);
		},

		render: function(){
			this.$el.html(this.template(this.model.toJSON()));
			return this;
		}

	});
	
	return FakeApLoginStationView;


});