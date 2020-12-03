define([
    'jquery',
    'arches',
    'views/list',
    'moment',
    'bindings/datepicker',
    'bindings/chosen',
    'views/components/simple-switch',
    'views/components/notification',
], function($, arches, ListView, moment) {
    var NotificationsList = ListView.extend({
        /**
        * A backbone view to manage a list of notification records
        * @augments ListView
        * @constructor
        * @name NotificationsList
        */

        singleSelect: true,

        initialize: function(options) {
            moment.locale('it');
            var self = this;

            this.items = options.items;
            this.helploading = options.helploading;

            
            ListView.prototype.initialize.apply(this, arguments);
            
            this.updateList = function() {
                self.helploading(true);
                
                $.ajax({
                    type: 'GET',
                    url: arches.urls.get_notifications,
                    data: {"unread_only": true}
                }).done(function(data) {
                    data.notifications.forEach(function(elem){
                        elem.displaytime = moment(elem.created).format('dddd, DD MMMM YYYY | hh:mm A');
                    });
                    self.items(data.notifications);
                    self.helploading(false);
                });
            };

            this.dismissAll = function() {
                var notifs = self.items().map(function(notif) { return notif.id; });
                
                $.ajax({
                    type: 'POST',
                    url: arches.urls.dismiss_notifications,
                    data: {"dismissals": JSON.stringify(notifs)},
                }).done(function() {
                    self.items.removeAll();
                });
            };
        }
    });

    return NotificationsList;
});
