define(
['jquery','lodash','backbone','semantic','utils/tpl',
'models/scanstatus-collection',
'views/status-scantable',
'views/status-scanchart'
],

function($, _, Backbone, $, tpl, ScanStatuses, StatusScanTableView, StatusScanChartView) {
	var StatusView = Backbone.View.extend({

		initialize: function(){
			this.template = _.template(tpl.get('status'));
			this.scanSignal = false;
		},

		render: function() {
			this.setElement(this.template());
			return this.el;
		},

		events: {
			"click .scan-start": "scanStart",
			"click .scan-pause": "scanPause",
			"click .scan-stop": "scanStop"
		},

		scanButtonState: function(state){
			switch(state){
				case 0:
					this.$el.find('.scan-start').addClass('disabled loading');
					this.$el.find('.scan-stop').removeClass('disabled');
					break;
				case 1:
					this.$el.find('.scan-pause').removeClass('disabled');
					break;
				case 2:
					this.$el.find('.scan-start').removeClass('disabled loading');
					this.$el.find('.scan-pause').addClass('disabled');
					break;
				case 3:
					this.$el.find('.scan-start').removeClass('disabled');
					this.$el.find('.scan-start').removeClass('loading');
					this.$el.find('.scan-pause').addClass('disabled');
					this.$el.find('.scan-stop').addClass('disabled');
					break;
				default:
					console.log('error');
					this.$el.find('.scan-start').addClass('disabled');
					this.$el.find('.scan-pause').addClass('disabled');
					this.$el.find('.scan-stop').addClass('disabled');
					break;
			}
		},


		scanStart: function(){
			if(this.scanStatusList==undefined){
				this.scanStatusList = new ScanStatuses();	
			}
			
			this.scanRun(10000);

			this.scanButtonState(0);

			this.$el.find('.scanOn').show();
		},

		scanPause: function(){
			this.scanSignal = false;

			this.scanButtonState(2);
		},

		scanStop: function(){
			this.scanSignal = false;

			this.scanSaveCheckModal();

			this.scanButtonState(3);

			this.$el.find('.scanOn').hide();
		},

		scanRun: function(interval){
			this.scanSignal = true;

			this.interval = interval;

			this.scanAction();
		},

		scanAction: function(){
			if( this.scanSignal ) {
				var self = this;
				this.scanStatusList.fetch({
					update:true,
					remove:false,
					success: function(){
						console.log('success in');
						if( self.scanSignal ) {
							if(self.scanStatusList.length>0 && self.statusScanTableView==undefined){
							    
								self.statusScanChartView = new StatusScanChartView({
									model: self.scanStatusList
								});
                            	console.log('chart view create');
								self.statusScanTableView = new StatusScanTableView({
									model: self.scanStatusList
								});

								self.$el.find('#scanTable').html(self.statusScanTableView.render().el);
								

								self.$el.find('#scanChart').html(self.statusScanChartView.render().el);
								self.statusScanChartView.dataSet().chartInit();
								console.log('input');
							}
							setTimeout(function(){
								self.scanAction();
							},self.interval);
							self.scanButtonState(1);
						}
					},
					error: function(){
						console.log('error');
					}
				});
			}
		},

		scanSaveCheckModal: function(){
			var self = this;
			console.log('/.');
			$('.scan-save.check').modal({
				allowMultiple:false,
				closable: false,
				onDeny: function(){
					console.log('on deny');
					self.scanStatusList.stop();
					self.scanClear();
					
				},
				onApprove: function(){
					self.saveToLocalStorage();
					self.scanStatusList.stop();
					self.scanClear();
				}
			}).modal('show');
		},

		scanClear: function(){
			if(this.statusScanTableView!=undefined){
				this.statusScanTableView.close();
				delete this.statusScanTableView;
			}
			if(this.statusScanChartView!=undefined){
				this.statusScanChartView.close();
				delete this.statusScanChartView;
			}
		},

		saveToLocalStorage: function(){
			console.log(this.scanStatusList.toJSON());
			var jsondata = this.scanStatusList.toJSON();
			jsondata = JSON.stringify(jsondata);
			localStorage.setItem('scannedAP',jsondata);
		}


	});

	return StatusView;


});