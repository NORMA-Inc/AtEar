define(
['jquery','lodash','backbone','semantic','utils/tpl','models/project-model'],

function($,_,Backbone,$,tpl,Project) {

	var ProjectListView = Backbone.View.extend({

		initialize: function(){
			this.template = _.template(tpl.get('project-list'));
			this.model.bind("reset",this.render,this);
			
		},

		events: {
			"click .add.button" : "appendNewProject"
		},

		semantic_ui: function(){
			this.$el.find('#add_project .dimmable').dimmer({
				on: 'hover'
			});
		},

		render: function(){
			this.setElement(this.template());

			this.semantic_ui();

			_.each(this.model.models,function(project) {
				this.appendProject(project);
			}, this);

			return this.el;
		},

		appendNewProject: function(){
			var cur_time = new Date().toLocaleString();
			this.$el.append(new ProjectListItemView({
				model: new Project({p_time:cur_time})
			}).editrender().el);
		},

		appendProject: function(project) {
			this.$el.append(new ProjectListItemView({
				model: project
			}).render().el);
		}


	});

	var ProjectListItemView = Backbone.View.extend({

		tagName: "div",

		className: "card",


		initialize: function(){
			this.template = _.template(tpl.get('project-list-item'));
			this.model.bind("change",this.render,this);
			this.model.bind("destroy",this.close,this);
		},

		render: function() {
			this.$el.html(this.template(this.model.toJSON()));
			return this;
		},

		editrender: function() {
			this.$el.html(this.template(this.model.toJSON()));
			this.editmode();
			return this;
		},

		events: {
			"click .remove.icon": "deleteProject",
			"click .write.icon" : "editmode",
			"click .save.button" : "saveProject",
			"click .go.button" : "goProject"
		},

		viewmode: function(){
			this.$el.removeClass('editing');
		},

		editmode: function(){
			this.$el.addClass('editing');
			this.$el.find('.p_name').focus();
		},

		saveProject: function(){
			this.viewmode();

			this.model.set({
				p_name: this.$el.find('.p_name').val(),
				p_desc: this.$el.find('.p_desc').val()
			})
			if (this.model.isNew()) {
				var self = this;
				app.projectList.create(this.model,{
					success: function(){
					}
				});
			} else {
				this.model.save();
			}
			
			return false;
		},

		deleteProject: function(){
			this.model.destroy();
			return false;
		},

		goProject: function(){
			app.navigate(this.model.id+'/status',{trigger:true});
		}

	});
	
	return ProjectListView;

});