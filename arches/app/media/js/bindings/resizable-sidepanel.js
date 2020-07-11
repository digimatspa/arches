define([
    'jquery',
    'knockout',
    'jquery-resizable'
], function($, ko, resizable) {
    ko.bindingHandlers.resizableSidepanel = {
        init: function(element, valueAccessor, allBindings, viewModel) {
            var $el = $(element);

             $el.resizableSafe({
               handleSelector: ".splitter",
               resizeHeight: false
             });
        }
    }

    return ko.bindingHandlers.resizableSidepanel;
});
