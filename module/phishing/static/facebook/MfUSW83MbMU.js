/*!CK:1379140887!*//*1425869128,*/

if (self.CavalryLogger) { CavalryLogger.start_js(["Ni62x"]); }

__d("MCoreInit",["AddressBar","Bootloader","ErrorUtils","MCache","MTabletLoader","MFacewebAndroidLink","MPageController","MViewport","MWildeLink","RemoteDevice","Resource","ServerJS","Stratcom","ix"],function(a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t){b.__markCompiled&&b.__markCompiled();function u(v){t.add(v.ixData);h.setResourceMap(v.resource_map);h.enableBootload(v.bootloadable);if(v.hideLocationBar)g.setupLoadListener();if(v.isWildeWeb)o.setupListeners();if(v.isFacewebAndroid)l.setupListeners();if(k.isTabletFrame)k.MTabletLink.initialize();s.mergeData(0);n.init();m.init();p.init();q.load(v.coreResources,function(){i.guard(function(){if(v.clearMCache)j.clear();if(v.onload)(new Function(v.onload))();if(v.onafterload)(new Function(v.onafterload))();(new r()).handle(v.serverJSData);s.invoke('m:root:render');},'onload')();});}f.init=u;},null);