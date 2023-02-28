$('#type').change(function () {
    opt = $(this).val();
    if (opt == "apple") {
        $("#pfx").collapse('hide');
        $("#zip").collapse('hide');
        $("#txt1").collapse('hide');
        $("#txt2").collapse('hide');
        $("#txt3").collapse('hide');
        $("#apple").collapse('show');
        $("#download").collapse('show');
    }
     if (opt == "zip") {
        $("#pfx").collapse('hide');
        $("#txt1").collapse('hide');
        $("#txt2").collapse('hide');
        $("#txt3").collapse('hide');
        $("#apple").collapse('hide');
        $("#zip").collapse('show');
        $("#download").collapse('show');
    }
    if (opt == "txt") {
        $("#download").collapse('hide');
        $("#pfx").collapse('hide');
        $("#zip").collapse('hide');
        $("#apple").collapse('hide');
        $("#txt1").collapse('show');
        $("#txt2").collapse('show');
        $("#txt3").collapse('show');
    }
    if (opt == "pfx") {
        $("#apple").collapse('hide');
        $("#zip").collapse('hide');
        $("#txt2").collapse('hide');
        $("#txt3").collapse('hide');
        $("#pfx").collapse('show');
        $("#txt1").collapse('show');
        $("#download").collapse('show');
    }
});