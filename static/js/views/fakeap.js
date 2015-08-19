define(
['jquery','lodash','backbone','semantic','utils/tpl',
'views/fakeap-connstation',
'views/fakeap-loginstation',
'models/fakeap-model'],

function($,_,Backbone,$,tpl,FakeApConnStationView,FakeApLoginStationView, FakeAp) {

	var FakeapView = Backbone.View.extend({

		initialize: function(){
			this.template = _.template(tpl.get('fakeap'));
			
			this.fakeapSignal = false;
		},

		render: function(){
			this.setElement(this.template());
			return this.el;
		},

		events: {
			"click .start.button": "start",
			"click .pause.button": "pause",
			"click .stop.button": "stop"
		},

		contextState: function(state){
			switch(state){
				case 0:
					this.$el.find('.start.button').addClass('disabled loading');
					this.$el.find('.stop.button').removeClass('disabled');
					this.form.find('.field').addClass('disabled');
					break;
				case 1:
					this.$el.find('.pause.button').removeClass('disabled');
					break;
				case 2:
					this.$el.find('.start.button').removeClass('disabled loading');
					this.$el.find('.pause.button').addClass('disabled');
					this.form.find('.field').removeClass('disabled');
					break;
				case 3:
					this.$el.find('.start.button').removeClass('disabled');
					this.$el.find('.start.button').removeClass('loading');
					this.$el.find('.pause.button').addClass('disabled');
					this.$el.find('.stop.button').addClass('disabled');
					this.form.find('.field').removeClass('disabled');
					break;
				default:
					this.$el.find('.start.button').addClass('disabled');
					this.$el.find('.pause.button').addClass('disabled');
					this.$el.find('.stop.button').addClass('disabled');
					break;
			}
		},
		
		afterRender: function(){
			this.form = this.$el.find('.ui.form');

			this.formReset();

		},

		formValidation: function(){
			this.ssidValidation();
			this.encValidation();
			var self = this;
			this.$el.find('select.dropdown').dropdown({
				onChange: function(value){
					var type;
					if(value == 'wep')
						type = 1;
					else if(value == 'wpa')
						type = 2;
					else
						type = 0;

					self.pwValidation(type);
				}
			});
		},

		start: function(){
			if(this.form.form('is valid')){
				this.contextState(0);

				var enc = this.form.form('get value','enc');
				var ssid = this.form.form('get value','ssid');
				var password = this.form.form('get value','password');

				this.fakeAp = new FakeAp({'enc':enc,'ssid':ssid,'password':password});

				this.fakeapRun(10000);
			}
		},

		fakeapRun: function(interval){
			//For POST request with options
			this.fakeAp.save();
			this.fakeapSignal = true;
			this.interval = interval;
			var self = this;
			setTimeout(function(){
				self.fakeapAction();
			},1000);
		},

		fakeapAction: function(){
			if( this.fakeapSignal ) {
				var self = this;
				this.fakeAp.fetch({
					success: function(){
						if( self.fakeapSignal ){
							var connstation = new Backbone.Collection(JSON.parse(self.fakeAp.get("connstation").replace(/'/g,"\"").replace(/None/g,'"None"').replace(/False/g,'"False"').replace(/: u"/g,': "')));
							var loginstation = new Backbone.Collection(JSON.parse(self.fakeAp.get("loginstation").replace(/'/g,"\"").replace(/None/g,'"None"').replace(/False/g,'"False"').replace(/: u"/g,': "')));
							self.fakeApConnStationView = new FakeApConnStationView({
								model: connstation
							});
							self.fakeApLoginStationView = new FakeApLoginStationView({
								model: loginstation
							});
							self.$el.find('#conn-station').html(self.fakeApConnStationView.render().el);
							self.$el.find('#login-station').html(self.fakeApLoginStationView.render().el);
	
							setTimeout(function(){
								self.fakeapAction();
							},self.interval);
							self.contextState(1);
						}
					},
					error: function() {
						setTimeout(function(){
							self.fakeapAction();
						},self.interval);
					}
				});
			}
		},

		pause: function(){
			this.fakeapSignal = false;
			this.contextState(2);
		},

		stop: function(){
			this.fakeapSignal = false;
			this.contextState(3);
			this.formReset();
			this.fakeapClear();
		},

		fakeapClear: function(){
			if(this.fakeApConnStationView!=undefined) {
				this.fakeApConnStationView.close();
				delete this.fakeApConnStationView;
			}
			if(this.fakeApLoginStationView!=undefined) {
				this.fakeApLoginStationView.close();
				delete this.fakeApLoginStationView;
			}
			Backbone.sync('delete',this.fakeAp,{});
			delete this.fakeAp;
		},	

		formReset: function(){
			this.form.form('reset');
			this.$el.find('.password.field').addClass('disabled').find('input').attr('disabled',true);
			this.formValidation();
		},

		ssidValidation: function(){
			this.form.form({
				on: 'change',
				inline: true,
				fields: {
					ssid_empty: {
						identifier: 'ssid',
						rules: [
						{
							type: 'empty',
							prompt: 'Please enter the ssid'
						}]
					}
				}
			});
		},

		encValidation: function(){
			this.form.form({
				on: 'change',
				inline: true,
				fields: {
					empty: {
						identifier: 'enc',
						rules: [
						{
							type: 'empty',
							prompt: 'Please select Encryption'
						}]
					}
				}
			})
		},

		pwValidation: function(type){
			this.form.form('set value','password','');
			switch(type){
				case 0:
					this.$el.find('.password.field').addClass('disabled').find('input').attr('disabled',true);
					break;
				case 1:
					this.$el.find('.password.field').removeClass('disabled').find('input').attr('disabled',false);
					this.form.form({
						on: 'change',
						inline: true,
						fields: {
							password_wep: {
								identifier: 'password',
								rules: [
								{
									type : 'regExp[/((^.{5}$)|(^.{13}$)|(^.{16}$))/]',
									prompt : 'Please enter exactly 5, 13, 16 characters'
								}]
							}
						}
					});
					break;
				case 2:
					this.$el.find('.password.field').removeClass('disabled').find('input').attr('disabled',false);
					this.form.form({
						on: 'change',
						inline: true,
						fields: {
							password_wpa: {
								identifier: 'password',
								rules: [
								{
									type: 'length[8]',
									prompt: 'Please enter at least 8 characters'
								}]
							}
						}
					});
					break;
				default:
					break;
			}
		}
	});
	
	return FakeapView;

});