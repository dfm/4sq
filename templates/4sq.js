(function () {

  "use strict";

  var fsq = window.foursquare = {};

  fsq.confirm_number = function () {
    var el = $("#phone-input");
    el.attr("disabled", "disabled");
    $("#phone-result").text("Confirming number.");
    $("#enter-code-modal").show();

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

  fsq.confirm_code = function () {
    var code = $("#code-input").val(),
        url = "{{ url_for('.confirm_code', code='') }}" + code;
    $.ajax({url: url,
            dataType: "json",
            success: fsq.code_response,
            error: fsq.code_error});
  };

  fsq.code_response = function (data) {
    $("#enter-code-modal").hide();
  };

  fsq.code_error = function (xhr, errorType, data) {
    $("#code-result").text(xhr.responseText);
  };

})();
