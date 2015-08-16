define(
['jquery','lodash','backbone','semantic','utils/tpl','libs/Chart.min'],

function($, _, Backbone, $, tpl,Chart) {
	var StatusScanChartView = Backbone.View.extend({

		tagName: 'div',

		className: 'ui centered grid',

		initialize: function(){
			console.log('init');
			this.template = _.template(tpl.get('status-scanchart'));
			this.model.bind("add",this.reRender,this);
			this.colorcode1 = ['#DB2828','#F2711C','#FBBD08','#B5CC18','#21BA45','#00B5AD','#2185D0','#6435C9','#A333C8','#E03997','#A5673F','#767676','#1B1C1D','#FF695E','#FF851B','#FFE21F','#D9E778','#2ECC40'];

			this.legend = "<div class=\"ui horizontal list\"> <% for (var i=0; i<segments.length; i++){%>\
									<div class=\"item\"><span class=\"ui empty circular label\" style=\"background-color:<%=segments[i].fillColor%>\"></span>\
									<span class=\"content\"><%if(segments[i].label){%><%=segments[i].label%><%}%></span></div><%}%></div>";
			
		},

		render: function(){
			console.log('chart render');
			this.$el.html(this.template());

			return this;
		},

		reRender: function(){
			console.log('chart re render');
			
			this.destroy().dataSet().chartInit();

			
			return this;
		},

		dataSet: function(){
			console.log('chart dataSet');
			var type_labels = this.model.distinctKey('type');
			var enc_labels = this.model.distinctKey('enc');
			var ch_labels = this.model.distinctKey('ch');
			var type_length = type_labels.length;
			var enc_length = enc_labels.length;
			var ch_length = ch_labels.length;

			this.typeData=[];
			for(var i=0; i< type_length; i++){
				var name = type_labels[i];
				var d = {
					value : this.model.where({type: name}).length,
					color : this.colorcode1[i],
					label : name
				};
				this.typeData[i] = d;
			}

			this.encData=[];
			var j = 0;
			for(var i=0; i< enc_length; i++){
				var name = enc_labels[i];
				if ( name != 'N/A') {
					var d = {
						value : this.model.where({enc: name}).length,
						color : this.colorcode1[i],
						label : name
					};
					this.encData[j++] = d;
				}
			}

			this.chData=[];
			var j = 0;
			for(var i=0; i< ch_length; i++){
				var name = ch_labels[i];
				if ( name != '') {
					var d = {
						value : this.model.where({ch: name}).length,
						color : this.colorcode1[i],
						label : name
					};
					this.chData[j++] = d;
				}
			}

			/*this.typeData = _.sortBy(this.typeData,'value');
			this.encData = _.sortBy(this.encData,'value');
			this.chData = _.sortBy(this.chData,'value');*/

			return this;

		},

		chartInit: function(){
			console.log('chartInit');
			Chart.defaults.global.responsive = true;

			this.ctx_type = this.$el.find('#typeChart').get(0).getContext('2d');
			this.ctx_enc = this.$el.find('#encChart').get(0).getContext('2d');
			this.ctx_ch = this.$el.find('#chChart').get(0).getContext('2d');

			this.typeChart = new Chart(this.ctx_type).Doughnut(this.typeData,{
				legendTemplate: this.legend
			});
			this.encChart = new Chart(this.ctx_enc).Doughnut(this.encData,{
				legendTemplate: this.legend
			});
			this.chChart = new Chart(this.ctx_ch).Doughnut(this.chData,{
				legendTemplate: this.legend
			});

			this.$el.find('#typeLegend').html(this.typeChart.generateLegend());
			this.$el.find('#encLegend').html(this.encChart.generateLegend());
			this.$el.find('#chLegend').html(this.chChart.generateLegend());
			console.log('chartInit finish');

			return this;
		},

		destroy: function(){
			this.typeChart.destroy();
			this.encChart.destroy();
			this.chChart.destroy();

			return this;
		}
	});
	
	return StatusScanChartView;

});