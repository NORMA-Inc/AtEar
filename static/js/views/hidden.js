define(
['jquery','lodash','backbone','semantic','utils/tpl','models/hidden-model'],

function($,_,Backbone,$,tpl, HiddenModel) {

	var HiddenView = Backbone.View.extend({

		initialize: function(){
			this.template = _.template(tpl.get('hidden'));
			this.model.bind("change",this.appendMessage,this);
		},

		render: function(){
			this.setElement(this.template());
			this.pulling(5000);
			console.log('hidden render');
			return this.el;
		},

		pulling: function(interval){
			console.log(interval);
			var self = this;
			this.model.fetch({
				success: function(){
					setTimeout(function(){
						self.pulling(interval);
					},interval);
				},
				error: function(){
					console.log('error');
				}
			})
		},

		appendMessage: function(){
			if(this.model.messageLength()){
				var messages = this.model.messageToCollection();

				_.each(messages.models,function(message){
					var newMsg = new HiddenMessageView({
						model: message
					}).render();
					this.$el.append(newMsg.el);
					newMsg.fadeIn();
				},this);
			}
		}

	});

	var HiddenMessageView = Backbone.View.extend({

		tagName: 'div',

		className: 'ui error message',

		initialize: function(){
			this.template = _.template(tpl.get('hidden-message'));
		},

		render: function() {
			this.$el.html(this.template(this.model.toJSON()));
			return this;
		},

		events: {
			"click .close.icon": "fadeOut"
		},

		fadeIn: function() {
			this.$el.transition({
				animation: 'fade left',
				duration: '1000ms'
			});

			return this;
		},

		fadeOut: function() {
			var self = this;
			this.$el.transition({
				animation: 'fade left',
				duration: '500ms',
				onHide : function(){
					self.close();
				}
			});
		}

	});
	
	return HiddenView;

});