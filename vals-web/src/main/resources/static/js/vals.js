window.Vals = {
    adesRequest: "",
    adesResponse: "",
    x509Request: "",
    x509Response: "",
    ersRequest: "",
    ersResponse: ""
};

let isDragAndDropSupported = function () {

    var div = document.createElement('div');
    return ('draggable' in div) || ('ondragstart' in div && 'ondrop' in div) && 'FormData' in window && 'FileReader' in window;
};

let showFiles = function (files) {

    var $form = $('#dropbox-val-ades'),
        $label = $form.find('label'),
        $input = $form.find('input[type="file"]');

    $label.text(files.length > 1 ? ($input.attr('data-multiple-caption') || '').replace(
        '{count}', files.length) : files[0].name);
};

let showSignFile = function (file, signType) {

    var $form = $('#dropbox-val-' + signType);

    $form.find('label[for="' + signType + '-sign-file"]').text(file.name);
};

let showDetachedFile = function (file, signType) {

    var $form = $('#dropbox-val-' + signType);
    let labelText = "";
    if (file.length > 1) {
        var i;
        for (i = 0; i < file.length; i++) {
            labelText += file[i].name;
            if (i < file.length - 1) {
                labelText += ", ";
            }
        }
    } else {
        labelText = file[0].name;
    }
    $form.find('label[for="' + signType + '-detach-file"]').text(labelText);
};

let resetFileInput = function (elt) {

    elt.wrap('<form>').closest('form').trigger('reset');
    elt.unwrap();
}

let checkCertExtension = function (fileName) {
    var certExtensions = ["crt", "cer", "pem", "der", "p7b", "p7c", "p12", "pfx"];
    var ext = fileName.substr(fileName.lastIndexOf('.') + 1);
    return certExtensions.includes(ext);
}

let showErrorMessage = function (signType, errorMessage) {
    let $form = $('#dropbox-val-' + signType);
    $form.removeClass('is-uploading');
    $('#dropbox-error-' + signType).html('<p class="red">' + errorMessage +'</p>').show();
    $('#trigger-validation-' + signType).hide();
    $('#reset-validation-' + signType).show().css('display', 'inline-block');
}

let callRequestApi = function (data, signType) {
    $.ajax({
        type: 'POST',
        url: window.location.origin + "/api/request",
        contentType: false,
        processData: false,
        cache: false,
        data: data,
        success: function (data) {
            if (signType === 'ers' && !data.profile[0].includes("EvidenceRecord")) {
                showErrorMessage(signType, "Please select evidence record file.");
            } else if (signType === 'x509' && !data.profile[0].includes("X.509")) {
                showErrorMessage(signType, "Please select x509 certificate file.");
            } else if (signType === 'ades' && (data.profile[0].includes("EvidenceRecord") || data.profile[0].includes("X.509"))) {
                showErrorMessage(signType, "Please select AdES signature file.");
            } else {
                callValidateApi(JSON.stringify(data), signType);
            }
        }, error: function (data) {
            showErrorMessage(signType, "An error occurred while generating the verify request. Please try again later.");
        }
    });
}

let callValidateApi = function (request, signType) {
    let $form = $('#dropbox-val-' + signType);
    $.ajax({
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        },
        type: 'POST',
        url: window.location.origin + "/api/validation",
        contentType: false,
        processData: false,
        cache: false,
        data: request,
        success: function (response) {
            $form.removeClass('is-uploading');
            $form.find('div.dropbox__error').hide();
            $form.find('.dropbox__icon').hide();
            $('label[for="' + signType + '-sign-file"]').hide();
            if (signType !== 'x509') {
               $('label[for="' + signType + '-detach-file"]').hide();
            }
            $('#trigger-validation-' + signType).hide();
            $('#reset-validation-' + signType).show().css('display', 'inline-block');
            if (signType === 'ades') {
                window.Vals.adesRequest = request;
                window.Vals.adesResponse = JSON.stringify(response);
            } else if (signType === 'x509') {
                window.Vals.x509Request = request;
                window.Vals.x509Response = JSON.stringify(response);
            } else if (signType === 'ers') {
                window.Vals.ersRequest = request;
                window.Vals.ersResponse = JSON.stringify(response);
            }

            var validationResult = '<p class="blue">' + response.result.resultMajor + '</p>';
            if (response.result.resultMinor) {
                validationResult += '<p class="blue"> '+ response.result.resultMinor + ' </p>';
            }
            $('#dropbox-success-' + signType).html(validationResult).show();
            $('#download-request-' + signType).show().css('display', 'inline-block');
            $('#download-response-' + signType).show().css('display', 'inline-block');
        }, error: function (response) {
            $form.removeClass('is-uploading');
            $('#dropbox-error-' + signType).html('<p class="red">An error occurred while validating the signature. Please try again later.</p>').show();
        }
    });
}

Vals.initAdesValidationForm = function () {

    var $adesInput = $('#dropbox-ades'),
        $fileInput =  $('#dropbox-file-ades'),
        droppedAdesFile = false,
        droppedAdesDetachedFile = false;

    if (isDragAndDropSupported()) {

        // $('.dropbox-val').addClass('has-advanced-upload');

        $adesInput.on('change drag dragstart dragend dragover dragenter dragleave drop', function(e) {
            e.preventDefault();
        })
            .on('dragover dragenter', function() {
                $adesInput.addClass('is-dragover');
            })
            .on('dragleave dragend drop', function() {
                $adesInput.removeClass('is-dragover');
            })
            .on('drop', function(e) {
                droppedAdesFile = e.originalEvent.dataTransfer.files[0];
                showSignFile(droppedAdesFile, 'ades');
                if (droppedAdesDetachedFile) {
                    $('#trigger-validation-ades').show().css('display', 'inline-block');
                }
            })
            .on('change', function (e) {
                droppedAdesFile = $('#ades-sign-file')[0].files[0];
                showSignFile(droppedAdesFile, 'ades');
                if (droppedAdesDetachedFile) {
                    $('#trigger-validation-ades').show().css('display', 'inline-block');
                }
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
                droppedAdesDetachedFile = e.originalEvent.dataTransfer.files;
                showDetachedFile(droppedAdesDetachedFile, 'ades');
                if (droppedAdesFile) {
                    $('#trigger-validation-ades').show().css('display', 'inline-block');
                }
            })
            .on('change', function (e) {
                droppedAdesDetachedFile = $('#ades-detach-file')[0].files;
                showDetachedFile(droppedAdesDetachedFile, 'ades');
                if(droppedAdesFile) {
                    $('#trigger-validation-ades').show().css('display', 'inline-block');
                }
            });
    }

    $('#trigger-validation-ades').on('click', function(e) {

        e.preventDefault();
        e.stopImmediatePropagation();

        let $form = $('#dropbox-val-ades');

        if ($form.hasClass('is-uploading')) return false;

        $form.addClass('is-uploading').removeClass('is-error');

        if (isDragAndDropSupported()) {
            e.preventDefault();

            var data = new FormData();
            data.append('signature', droppedAdesFile);
            data.append('documents', droppedAdesDetachedFile[0]);
            callRequestApi(data, 'ades');
        }
    });
};

Vals.initX509ValidationForm = function () {
    var $x509Input = $('#dropbox-x509'),
        droppedX509File = false;

    if (isDragAndDropSupported()) {

        // $('.dropbox-val').addClass('has-advanced-upload');

        $x509Input.on('change drag dragstart dragend dragover dragenter dragleave drop', function(e) {
            e.preventDefault();
        })
            .on('dragover dragenter', function() {
                $x509Input.addClass('is-dragover');
            })
            .on('dragleave dragend drop', function() {
                $x509Input.removeClass('is-dragover');
            })
            .on('drop', function(e) {
                droppedX509File = e.originalEvent.dataTransfer.files[0];
                showSignFile(droppedX509File, 'x509');
                $('#trigger-validation-x509').show().css('display', 'inline-block');
            })
            .on('change', function (e) {
                droppedX509File = $('#x509-sign-file')[0].files[0];
                showSignFile(droppedX509File, 'x509');
                $('#trigger-validation-x509').show().css('display', 'inline-block');
            });
    }

    $('#trigger-validation-x509').on('click', function(e) {

        e.preventDefault();
        e.stopImmediatePropagation();

        let $form = $('#dropbox-val-x509');

        if ($form.hasClass('is-uploading')) return false;

        $form.addClass('is-uploading').removeClass('is-error');

        if (isDragAndDropSupported()) {
            e.preventDefault();
            var data = new FormData();
            data.append('signature', droppedX509File);
            // if (checkCertExtension(droppedX509File.name)) {
                callRequestApi(data, 'x509');
            // } else {
            //    showErrorMessage('x509', "Please select the certificate file.");
            // }
        }
    });
};

Vals.initErsValidationForm = function () {

    var $ersInput = $('#dropbox-ers'),
        $fileInput =  $('#dropbox-file-ers'),
        droppedErsFile = false,
        droppedErsDetachedFile = false;

    if (isDragAndDropSupported()) {

        // $('.dropbox-val').addClass('has-advanced-upload');

        $ersInput.on('change drag dragstart dragend dragover dragenter dragleave drop', function(e) {
            e.preventDefault();
        })
            .on('dragover dragenter', function() {
                $ersInput.addClass('is-dragover');
            })
            .on('dragleave dragend drop', function() {
                $ersInput.removeClass('is-dragover');
            })
            .on('drop', function(e) {
                droppedErsFile = e.originalEvent.dataTransfer.files[0];
                showSignFile(droppedErsFile, 'ers');
                if (droppedErsDetachedFile) {
                    $('#trigger-validation-ers').show().css('display', 'inline-block');
                }
            })
            .on('change', function (e) {
                droppedErsFile = $('#ers-sign-file')[0].files[0];
                showSignFile(droppedErsFile, 'ers');
                if (droppedErsDetachedFile) {
                    $('#trigger-validation-ers').show().css('display', 'inline-block');
                }
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
                droppedErsDetachedFile = e.originalEvent.dataTransfer.files;
                showDetachedFile(droppedErsDetachedFile, 'ers');
                if (droppedErsFile) {
                    $('#trigger-validation-ers').show().css('display', 'inline-block');
                }
            })
            .on('change', function (e) {
                droppedErsDetachedFile = $('#ers-detach-file')[0].files;
                showDetachedFile(droppedErsDetachedFile, 'ers');
                if(droppedErsFile) {
                    $('#trigger-validation-ers').show().css('display', 'inline-block');
                }
            });
    }

    $('#trigger-validation-ers').on('click', function(e) {

        e.preventDefault();
        e.stopImmediatePropagation();

        let $form = $('#dropbox-val-ers');

        if ($form.hasClass('is-uploading')) return false;

        $form.addClass('is-uploading').removeClass('is-error');

        if (isDragAndDropSupported()) {
            e.preventDefault();

            var data = new FormData();
            data.append('signature', droppedErsFile);
            for (i = 0; i < droppedErsDetachedFile.length; i++) {
                data.append('documents', droppedErsDetachedFile[i]);
            }
            callRequestApi(data, 'ers');
        }
    });
};

Vals.initResultDownloadButtons = function() {

    $('#download-request-ades').on('click', function () {
        saveAs(new Blob([window.Vals.adesRequest], {'type': 'application/json'}), "request.json");
    });

    $('#download-response-ades').on('click', function () {
        saveAs(new Blob([window.Vals.adesResponse], {'type': 'application/json'}), "response.json");
    });

    $('#download-request-x509').on('click', function () {
        saveAs(new Blob([window.Vals.x509Request], {'type': 'application/json'}), "request.json");
    });

    $('#download-response-x509').on('click', function () {
        saveAs(new Blob([window.Vals.x509Response], {'type': 'application/json'}), "response.json");
    });

    $('#download-request-ers').on('click', function () {
        saveAs(new Blob([window.Vals.ersRequest], {'type': 'application/json'}), "request.json");
    });

    $('#download-response-ers').on('click', function () {
        saveAs(new Blob([window.Vals.ersResponse], {'type': 'application/json'}), "response.json");
    });
}

Vals.initResetButtons = function() {

    $('#reset-validation-ades').on('click', function () {
        let $form = $('#dropbox-val-ades');
        $form[0].reset();
        $form.removeClass('is-uploading');
        $form.find('div.dropbox__success').hide().html("");
        $form.find('div.dropbox__download').hide();
        $form.find('div.dropbox__validation').show();
        $form.find('div.dropbox__error').hide();
        $form.find('.dropbox__icon').show();
        $('#trigger-validation-ades').show();
        $form.find('label[for="ades-sign-file"]').text('Choose AdES signature file').show();
        $form.find('label[for="ades-detach-file"]').text('Choose accompanying file').show();
        resetFileInput($('#ades-sign-file'));
        resetFileInput($('#ades-detach-file'));
        Vals.initAdesValidationForm();
    });

    $('#reset-validation-x509').on('click', function () {
        let $form = $('#dropbox-val-x509');
        $form[0].reset();
        $form.removeClass('is-uploading');
        $form.find('div.dropbox__success').hide().html("");
        $form.find('div.dropbox__download').hide();
        $form.find('div.dropbox__validation').show();
        $form.find('div.dropbox__error').hide();
        $form.find('.dropbox__icon').show();
        $('#trigger-validation-x509').show();
        $form.find('label[for="x509-sign-file"]').text('Choose X.509 certificate file').show();
        resetFileInput($('#x509-sign-file'));
        Vals.initX509ValidationForm();
    });

    $('#reset-validation-ers').on('click', function () {
        let $form = $('#dropbox-val-ers');
        $form[0].reset();
        $form.removeClass('is-uploading');
        $form.find('div.dropbox__success').hide().html("");
        $form.find('div.dropbox__download').hide();
        $form.find('div.dropbox__validation').show();
        $form.find('div.dropbox__error').hide();
        $form.find('.dropbox__icon').show();
        $('#trigger-validation-ers').show();
        $form.find('label[for="ers-sign-file"]').text('Choose Evidence Record file').show();
        $form.find('label[for="ers-detach-file"]').text('Choose accompanying file').show();
        resetFileInput($('#ers-sign-file'));
        resetFileInput($('#ers-detach-file'));
        Vals.initX509ValidationForm();
    });
}

Vals.init = function () {
    Vals.initAdesValidationForm();
    Vals.initX509ValidationForm();
    Vals.initErsValidationForm();
    Vals.initResetButtons();
    Vals.initResultDownloadButtons();
};