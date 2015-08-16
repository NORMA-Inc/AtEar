define(
['jquery','lodash','backbone','semantic','utils/tpl'
,'models/wids-collection'
,'views/wids-statistic'
,'views/wids-table'
],

function($,_,Backbone,$,tpl,WidsList, WidsStatisticView, WidsTableView) {

	var WidsView = Backbone.View.extend({

		initialize: function(){
			this.template = _.template(tpl.get('wids'));
			
		},

		render: function(){
			this.setElement(this.template());
			return this.el;
		},

		afterRender: function(){
			this.widsList = new WidsList();
			var self = this;
			this.widsList.fetch({
				success: function(){
					self.widsStatisticView = new WidsStatisticView({
						model : self.widsList
					});

					self.widsTableView = new WidsTableView({
						model : self.widsList
					});

					self.$el.find('#widsStatistic').html(self.widsStatisticView.render().el);
					self.widsStatisticView.afterRender();
					
					self.$el.find('#widsTable').html(self.widsTableView.render().el);
				},
				error: function(){
					console.log('error');
				}
			});
		}

	});
	
	return WidsView;

});