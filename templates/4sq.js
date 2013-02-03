(function () {

  "use strict";

  var fsq = window.foursquare = {};

  fsq.confirm_number = function () {
    var el = $("#phone-input");
    el.attr("disabled", "disabled");
    $("#phone-result").text("Confirming number.");
    $("#modal-input").show();

    // Submit the API request.
    var url = "{{ url_for('check_number') }}",
        params = {number: el.val()};
    $.ajax({url: url,
            dataType: "json",
            data: params,
            success: fsq.number_response});
  };

  fsq.number_response = function (data) {
    $("#phone-input").val(data.number);
  };

})();
