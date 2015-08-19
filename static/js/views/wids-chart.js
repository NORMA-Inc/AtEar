define(
['jquery','lodash','backbone','semantic','utils/tpl','libs/Chart.min'],

function($, _, Backbone, $, tpl,Chart) {
	var WidsChartView = Backbone.View.extend({

		tagName: 'div',

		className: 'ui raised segments',

		initialize: function(){
			this.template = _.template(tpl.get('wids-chart'));
		},

		render: function(){
			this.$el.html(this.template());

			return this;
		},

		dataSet: function(){
			var wids_labels = ['Dissassocation Flood',
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
			var wids_length = wids_labels.length;
			this.widsData={};
			this.DataSet = [];
			for(var i=0; i< wids_length; i++){
				var name = wids_labels[i];
				this.DataSet[i] = this.model.where({attack: name}).length
			}

			var d = [{
				label: "Attack Type Dataset",
				fillColor: "rgba(220,220,220,0.5)",
				strokeColor: "rgba(220,220,220,0.8)",
				highlightFill: "rgba(220,220,220,0.75)",
				highlightStroke: "rgba(220,220,220,1)",
				data: this.DataSet
			}];

			this.widsData = {
				labels: wids_labels,
				datasets: d
			};

			return this;
		},

		chartInit: function(){
			Chart.defaults.global.responsive = true;
			this.ctx_wids = this.$el.find('.widschart').get(0).getContext('2d');

			this.widsChart = new Chart(this.ctx_wids).Bar(this.widsData,{});


			return this;
		}
	});
	
	return WidsChartView;

});