window.ValS = {};

let isDragAndDropSupported = function () {

    var div = document.createElement('div');
    return ('draggable' in div) || ('ondragstart' in div && 'ondrop' in div) && 'FormData' in window && 'FileReader' in window;
};

let showFiles = function (files) {

    var $form = $('.dropbox'),
        $label = $form.find('label'),
        $input = $form.find('input[type="file"]');

    $label.text(files.length > 1 ? ($input.attr('data-multiple-caption') || '').replace(
        '{count}', files.length) : files[0].name);
};

let showSignatureFile = function (file) {

    var $form = $('.dropbox.validate');

    $form.find('label[for="file-signature"]').text(file.name);
};

let showFileToValidate = function (file) {

    var $form = $('.dropbox.validate');

    $form.find('label[for="file-signed"]').text(file.name);
};

let initButtons = function () {

    $('.button.generate').click(function () {
        $('div.validate').hide();
        $('div.generate').show();
        $('.dropbox__icon').show();
        $('.dropbox__success').hide();
        $('.dropbox__error').hide();
        $('#trigger-generation').hide();
        $('#reset-generation').hide();
    });

    $('.button.validate').click(function () {
        $('div.validate').show();
        $('.dropbox__icon').show();
        $('div.validate').children().show();
        $('div.generate').hide();
        $('#trigger-validation').hide();
        $('#reset-validation').hide();
    });
};

ValS.initValidationForm = function () {

    var $signatureInput = $('#file-signature'),
        $fileInput =  $('#file-signed'),
        droppedSignatureFile = false,
        droppedFile = false;

    $('form.dropbox').show();
    $('.result').hide();

    if (isDragAndDropSupported()) {

        $('.dropbox.validate').addClass('has-advanced-upload');

        $signatureInput.on('change drag dragstart dragend dragover dragenter dragleave drop', function(e) {
            e.preventDefault();
        })
            .on('dragover dragenter', function() {
                $signatureInput.addClass('is-dragover');
            })
            .on('dragleave dragend drop', function() {
                $signatureInput.removeClass('is-dragover');
            })
            .on('drop', function(e) {
                $signatureInput = e.originalEvent.dataTransfer.files[0];
                showSignatureFile($signatureInput);
                if (droppedFile) {
                    $('#trigger-validation').show().css('display', 'inline-block');
                }
            })
            .on('change', function (e) {
                droppedSignatureFile = $('#file-signature')[0].files[0];
                showSignatureFile(droppedSignatureFile);
                $('#trigger-validation').show().css('display', 'inline-block');
            });

        $fileInput.on('change drag dragstart dragend dragover dragenter dragleave drop', function(e) {
            e.preventDefault();
        })
            .on('dragover dragenter', function() {
                $fileInput.addClass('is-dragover');
            })
            .on('dragleave dragend drop', function() {
                $fileInput.removeClass('is-dragover');
            })
            .on('drop', function(e) {
                droppedFile = e.originalEvent.dataTransfer.files[0];
                showFileToValidate(droppedFile);
                if (droppedSignatureFile) {
                    $('#trigger-validation').show().css('display', 'inline-block');
                }
            })
            .on('change', function (e) {
                droppedFile = $('#file-signed')[0].files[0];
                showFileToValidate(droppedFile);
                if(droppedSignatureFile) {
                    $('#trigger-validation').show().css('display', 'inline-block');
                }
            });
    }

    $('#trigger-validation').on('click', function(e) {

        e.preventDefault();
        e.stopImmediatePropagation();

        let $form = $('.dropbox-val');

        if ($form.hasClass('is-uploading')) return false;

        $form.addClass('is-uploading').removeClass('is-error');

        if (isDragAndDropSupported()) {
            e.preventDefault();

            var data = new FormData();
            data.append('signature', droppedSignatureFile);
            data.append('documents', droppedFile);

            displayProcessMessage("Requesting VerifyRequest...");

            $.ajax({
                type: 'POST',
                url: window.location.origin + "/api/request",
                contentType: false,
                processData: false,
                cache: false,
                data: data,
                success: function (data) {
                    displayProcessMessage("Received VerifyRequest, will request validation now...");
                    $('.dropbox__icon').hide();
                    $('label[for="file-signature"]').hide();
                    $('label[for="file-signed"]').hide();
                    $('.dropbox__button.validate').hide();
                    $('.dropbox__success.validate').html('<p>' + data.resultMajor + '</p><p>'+ data.resultMinor + '</p>').show();
                    $('#trigger-validation').hide();
                    $('#reset-validation').show().css('display', 'inline-block');
                    submitVerifyRequest(JSON.stringify(data));
                }, error: function (data) {
                    $('.dropbox__error.validate').html('<p>An error occurred while validating. Please try again later.</p>');
                    $('#trigger-validation').hide();
                    $('#reset-validation').show().css('display', 'inline-block');;
                }
            });
        }
    });
};

let submitVerifyRequest = function(verifyRequest) {

    let url = window.location.origin + "/api/validation";

    $.ajax({
        type: 'POST',
        url: url,
        contentType: 'application/json',
        data: verifyRequest,
        success: function (response) {
            parseVerifyResponse(response);
            saveVerifyResponse(response);
        },
        error: function () {
            parseVerifyResponse(null, true);
        }
    });
};

let parseVerifyResponse = function(verifyResponse, error) {

    if (error) {
        displayResult(null, null, true);
    }

    let globalResult = verifyResponse.result.resultMajor;

    if (globalResult == "urn:oasis:names:tc:dss:1.0:resultmajor:Success") {
        console.log(verifyResponse);
        if (verifyResponse.appliedProfile.length > 0 && verifyResponse.appliedProfile[0] == "urn:oasis:names:tc:dss:1.0:profiles:EvidenceRecord") {
            displayResult(verifyResponse.result.resultMajor, verifyResponse.result.resultMinor);
        } else {
            let result = verifyResponse.optionalOutputs.individualReport[0].result;
            displayResult(result.resultMajor, result.resultMinor, false);
        }
    } else {
        displayResult(null, null, true);
    }
};

let displayResult = function (resultMajor, resultMinor, error) {

    $('.message').text();
    $('.message').hide();
    $('.result-major').text();
    $('.result-minor').text();

    if (error || (resultMajor == null && resultMinor == null)) {
        $('.result-major').text("Error processing your request");
    }

    $('form').hide()

    $('.result-major').html("<b>Main result: </b>" + resultMajor);
    if (resultMinor != 'null' && resultMinor != null) {
        $('.result-minor').html("<b>Sub result: </b>" + resultMinor);
    }
    
    $('.result').show();
    $('.result-major').show();
    $('.result-minor').show();
}

let saveVerifyResponse = function (response) {

  let json = JSON.stringify(response);

  let blob = new Blob([json], {'type': 'application/json'});
  saveAs(blob, 'verifyresponse.json');
};

let displayProcessMessage = function (message) {

    $('.message').text(message);
    $('.message').show();
};

let handleFormError = function (form) {

    form.removeClass('is-uploading');
    form.addClass('is-error');
};

let resetFileInput = function (elt) {

    elt.wrap('<form>').closest('form').trigger('reset');
    elt.unwrap();
};

ValS.initResetButtons = function() {

    $('#reset-validation').on('click', function () {
        let $form = $('form.dropbox');
        $form[0].reset();

        $form.removeClass('is-uploading');
        $form.find('div.dropbox__success').hide().html("");
        $form.find('div.dropbox__validation').show();
        $form.find('.dropbox__icon').show();
        $form.find('label[for="file-signature"]').text('Choose signature file').show();
        $form.find('label[for="file-signed"]').text('Choose detached content').show();
        resetFileInput($('#file-signature'));
        resetFileInput($('#file-signed'));
        ValS.initValidationForm();
        $(this).hide();
    });
};

ValS.init = function () {

    ValS.initValidationForm();
    ValS.initResetButtons();
    initButtons();
};