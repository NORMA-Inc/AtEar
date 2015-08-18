define(
['jquery','lodash','backbone','semantic','utils/tpl'],

function($, _, Backbone, $, tpl) {
	var HeaderView = Backbone.View.extend({
		
		tagName: "div",

		className: "ui container mainmenu",

		initialize: function(){
			this.template = _.template(tpl.get('header'));
		},


		render: function() {
			this.$el.html(this.template());
			
			this.widsCheckbox();
			return this;
		},
		
		activeMenu: function(number){
			number = number.toString();
			$('a.active.item').removeClass('active');
			$('.'+number+'.item').addClass('active');

			return this;
		},

		widsCheckbox: function(){
			var widsOption = localStorage.getItem('wids');
			if(widsOption==1){
				this.$el.find('.ui.checkbox').checkbox('set checked');	
			}
			else {
				this.$el.find('.ui.checkbox').checkbox('set unchecked');
			}
			this.$el.find('.ui.checkbox').checkbox({
				onChecked: function(){
					app.hiddenModel.setWidsOption(1);
				},
				onUnchecked: function(){
					app.hiddenModel.setWidsOption(0);
				}
			});
			this.$el.find('.ui.checkbox').popup();
			
		}	

	});

	return HeaderView;

});