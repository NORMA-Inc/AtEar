define(
['jquery','lodash','backbone','semantic','utils/tpl','libs/Chart.min'],

function($, _, Backbone, $, tpl,Chart) {
	var WidsStatisticView = Backbone.View.extend({

		tagName: 'div',

		className: 'ui raised segments',

		initialize: function(){
			this.template = _.template(tpl.get('wids-statistic'));
		},

		render: function(){
			this.$el.html(this.template());

			return this;
		},

		dataSet: function(){
			this.wids_labels = ['Dissassocation Flood',
							'Deauth Flood',
							'Wessid-NG Attack',
							'Korek ChopChop Attack',
							'Fragmentation PRGA Attack',
							'MDK Micheal shutdown Exploitation (TKIP)',
							'Attack by TKIPTUN-NG',
							'Authentication DOS',
							'Association Flood',
							'High amount of association sent',
							'Suspect Rouge AP',
							'Detected Beacon Flood'];
			this.color_names = ['red','orange','yellow','olive','green','teal','blue','violet','purple','pink','brown','grey'];
			this.wids_length = this.wids_labels.length;
			this.DataSet = [];
			for(var i=0; i< this.wids_length; i++){
				var name = this.wids_labels[i];
				this.DataSet[i] = this.model.where({attack: name}).length
			}
			return this;
		},

		afterRender: function(){
			this.dataSet();

			var Statistic = Backbone.Model.extend({});
			for(var i=0; i<this.wids_length; i++){
				var statistic = new Statistic({value: this.DataSet[i], label: this.wids_labels[i], color: this.color_names[i]});
				this.appendList(statistic);
			}
		},

		appendList: function(statistic){
			this.$el.find('.ui.statistics').append(new WidsStatisticListView({
				model: statistic
			}).render().el);
		}


	});

	var WidsStatisticListView = Backbone.View.extend({

		tagName: "div",

		className: "two wide column statistic",

		initialize: function(){
			this.template = _.template(tpl.get('wids-statistic-list'));
			this.model.bind("change", this.render,this);
			this.model.bind("destroy", this.close, this);
		},

		render: function(){
			this.$el.html(this.template(this.model.toJSON()));
			return this;
		}
	})
	
	return WidsStatisticView;

});