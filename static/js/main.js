require([
	'jquery',
	'lodash',
	'backbone',
    'views/hidden',
    'views/header-menu',
	'views/project-list',
    'views/status',
    'views/fakeap',
    'views/pentest',
    'views/wids',
	'utils/tpl',
    'models/hidden-model',
	'models/project-model',
	'models/project-collection'
],

function($, _, Backbone, HiddenView, HeaderView, 
    ProjectListView, StatusView, FakeapView, PentestView, WidsView, 
    tpl, HiddenModel, scanSaveCheckModal,Project, Projects){
	Backbone.View.prototype.close = function() {
        if (this.beforeClose) {
            this.beforeClose();
        }
        this.remove();
        this.unbind();
    };

    var AppRouter = Backbone.Router.extend({
    	initialize:function(){
            this.hidden();
            this.statusView = new StatusView();

    	},
    	
    	routes: {
            "": "redirect",
    		"status": "status",
            "fakeap": "fakeap",
            "pentest": "pentest",
            "wids": "wids"
    	},

        redirect: function(){
            app.navigate("status",{trigger:true});
        },

        hidden: function(){
            if( this.hiddenView == undefined ) {
                this.hiddenModel = new HiddenModel();
                this.hiddenView = new HiddenView({
                    model: this.hiddenModel
                });
                $('body').append(this.hiddenView.render());
            }
        },

        status: function(){
            this.before(function() {

                this.headerView.activeMenu(1);
                this.showView('#content',this.statusView);
            });
        },

        fakeap: function(){
            this.before(function() {
                if (this.statusView.scanSignal) {
                    this.scanSignalCheckModal()
                }
                else{
                    this.headerView.activeMenu(3);
                    this.fakeapView = new FakeapView();
                    this.showView('#content', this.fakeapView);
                    this.fakeapView.afterRender();
                }
            });
        },

        pentest: function(){
            this.before(function() {
                if (this.statusView.scanSignal) {
                    this.scanSignalCheckModal()
                }
                else {
                    this.headerView.activeMenu(2);
                    this.pentestView = new PentestView();
                    this.showView('#content', this.pentestView);
                    this.pentestView.afterRender();
                }
            })
        },

        wids: function(){
            this.before(function() {
                if (this.statusView.scanSignal) {
                    this.scanSignalCheckModal()
                }
                else{
                    this.headerView.activeMenu(4);
                    this.widsView = new WidsView();
                    this.showView('#content',this.widsView);
                    this.widsView.afterRender();
                }
            });
        },

    	showView: function(selector, view) {
    		if (this.currentView) this.currentView.close();
            $('body>.ui.popup').remove();
            $('body>.ui.modals').remove();
    		$(selector).html(view.render());
    		this.currentView = view;
    		return view;
    	},

        scanSignalCheckModal: function(){
			var self = this;
			$('.error-scan.check').modal({

			}).modal('show');
		},

        before: function(callback) {
            if ( this.headerView ) {
                this.headerView.render();
                if (callback) callback.call(this);
            } else {
                this.headerView = new HeaderView();
                $('#header').html(this.headerView.render().el);
                if (callback) callback.call(this);
            }

        }
    });
    tpl.loadTemplates([
        'header',
        'hidden',
        'hidden-message',
    	'project-list',
    	'project-list-item',
        'status',
        'status-scantable',
        'status-scantable-list',
        'status-scanchart',
        'fakeap',
        'fakeap-connstation',
        'fakeap-connstation-list',
        'fakeap-loginstation',
        'fakeap-loginstation-list',
        'pentest',
        'pentest-scantable-empty',
        'pentest-scantable',
        'pentest-scantable-list',
        'pentest-option',
        'pentest-result',
        'pentest-result-list',
        'wids',
        'wids-statistic',
        'wids-statistic-list',
        'wids-chart',
        'wids-table',
        'wids-table-list'], 
    	function() {
        	window.app = new AppRouter();
        	Backbone.history.start();
        }
    );
}); //End require

