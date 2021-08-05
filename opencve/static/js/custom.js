var csrftoken = $('meta[name=csrf-token]').attr('content');

$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        }
    }
});


(function($){
    "use strict";

    // Subscriptions handler
    $('.subscribe').click(function() {
        var button = $(this)

        var action = $(button).attr('id').split('_')[0];
        var obj = $(button).attr('id').split('_')[1];
        var id = $(button).attr('id').split('_')[2];

        $.ajax({
            url: '/subscriptions',
            data: { 'action': action, 'obj': obj, "id": id },
            dataType: 'json',
            type: 'POST',
            success: function(data) {
                if ( data.status == 'ok' ) {
                    $(button).toggleClass('btn-default btn-danger');

                    if ( $(button).text().trim() == 'Subscribe' ) {
                        $(button).text('Unsubscribe');
                        $(button).attr("id", $(button).attr('id').replace('subscribe', 'unsubscribe'));
                    } else {
                        $(button).text('Subscribe');
                        $(button).attr("id", $(button).attr('id').replace('unsubscribe', 'subscribe'));
                    }
                }
            }
        });
    });

    // Remove a header row in Webhook integration
    function removeHeader() {
        $('.remove-header').off('click').on('click', function() {
            $(this).parents('.form-header').remove();
            return false;
        });
    }
    removeHeader();

    // Add a header row in Webhook integration
    $('#add-header').click(function() {
        var headers = $(this).prev('#headers');
        var idx = $(this).data("count") + 1;
        var html = '<div class="form-group form-header">' +
                    '<div class="row" id="header-' + idx + '">' +
                    '<div class="col-md-5"><input class="form-control" id="headers-' + idx + '-name" name="headers-' + idx + '-name" placeholder="Header" required="" type="text"></div>' +
                    '<div class="col-md-5"><input class="form-control" id="headers-' + idx + '-value" name="headers-' + idx + '-value" placeholder="Value" required="" type="text"></div>' +
                    '<div class="col-md-1"><button class="remove-header btn btn-default"><i class="fa fa-trash"></i></button></div>' +
                    '</div>' +
                    '</div>';

        headers.append(html);
        removeHeader();
        $(this).data("count", idx);
        return false;
    });

})(window.jQuery);