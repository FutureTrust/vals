window.Ers = {};

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

let showERSFile = function (file) {

    var $form = $('.dropbox-val');

    $form.find('label[for="ers-validate"]').text(file.name);
};

let showFileToValidate = function (file) {

    var $form = $('.dropbox-val');

    $form.find('label[for="file-validate"]').text(file.name);
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

let digestFile = function (file) {

    return new Promise(function(resolve, reject) {
       var reader = new FileReader();
       reader.onload = function (e) {
           if (e.target.readyState == FileReader.DONE) {
               var digest = getFileDigest(e.target.result);
               resolve(digest);
           }
       };
       reader.onerror = function () {
           reject(handleFormError($('.dropbox')));
       };
       reader.readAsBinaryString(file);
    });
};

let getFileDigest = function(bytes) {
    return CryptoJS.enc.Base64.stringify(CryptoJS.SHA256(bytes));
};

Ers.initValidationForm = function () {

    var $ersInput = $('#dropbox-ers'),
        $fileInput =  $('#dropbox-file'),
        droppedERSFile = false,
        droppedFile = false;

    if (isDragAndDropSupported()) {

        $('.dropbox.validate').addClass('has-advanced-upload');

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
                droppedERSFile = e.originalEvent.dataTransfer.files[0];
                showERSFile(droppedERSFile);
                if (droppedFile) {
                    $('#trigger-validation').show().css('display', 'inline-block');
                }
            })
            .on('change', function (e) {
                droppedERSFile = $('#ers-validate')[0].files[0];
                showERSFile(droppedERSFile);
                if (droppedFile) {
                    $('#trigger-validation').show().css('display', 'inline-block');
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
                droppedFile = e.originalEvent.dataTransfer.files[0];
                showFileToValidate(droppedFile);
                if (droppedERSFile) {
                    $('#trigger-validation').show().css('display', 'inline-block');
                }
            })
            .on('change', function (e) {
                droppedFile = $('#file-validate')[0].files[0];
                showFileToValidate(droppedFile);
                if(droppedERSFile) {
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
            data.append('ersFile', droppedERSFile);
            data.append('dataObjects', droppedFile);

            $.ajax({
                type: 'POST',
                url: window.location.origin + "/api/validate",
                contentType: false,
                processData: false,
                cache: false,
                data: data,
                success: function (data) {
                    $('.dropbox__icon').hide();
                    $('label[for="ers-validate"]').hide();
                    $('label[for="file-validate"]').hide();
                    $('.dropbox__button.validate').hide();
                    $('.dropbox__success.validate').html('<p>' + data.resultMajor + '</p><p>'+ data.resultMinor + '</p>').show();
                    $('#trigger-validation').hide();
                    $('#reset-validation').show().css('display', 'inline-block');;
                }, error: function (data) {
                    $('.dropbox__error.validate').html('<p>An error occurred while validating the Evidence Record. Please try again later.</p>');
                    $('#trigger-validation').hide();
                    $('#reset-validation').show().css('display', 'inline-block');;
                }
            });
        }
    });
};

Ers.initUploadForm = function () {

    var $form = $('.dropbox.generate');

    if (isDragAndDropSupported()) {

        $form.addClass('has-advanced-upload');

        var droppedFiles = false;

        $form.on('change drag dragstart dragend dragover dragenter dragleave drop', function(e) {
            e.preventDefault();
        })
            .on('dragover dragenter', function() {
                $form.addClass('is-dragover');
            })
            .on('dragleave dragend drop', function() {
                $form.removeClass('is-dragover');
            })
            .on('drop', function(e) {
                droppedFiles = e.originalEvent.dataTransfer.files;
                showFiles(droppedFiles);
                $('#trigger-generation').show().css('display', 'inline-block');
            })
            .on('change', function (e) {
                droppedFiles = $('#file-ers')[0].files;
                showFiles(droppedFiles);
                $('#trigger-generation').show().css('display', 'inline-block');
            });
    }

    $('#trigger-generation').on('click', function(e) {

        e.preventDefault();
        e.stopImmediatePropagation();

        if ($form.hasClass('is-uploading')) return false;

        $form.addClass('is-uploading').removeClass('is-error');

        if (isDragAndDropSupported()) {
            e.preventDefault();

            if (droppedFiles) {
                showFiles(droppedFiles);
                let filesArray = Array.from(droppedFiles),
                    promises = filesArray.map(file => digestFile(file));

                Promise.all(promises).then(function(digests) {

                    $.ajax({
                        type: 'POST',
                        url: window.location.origin + "/api/ers",
                        data: {
                            digests: digests.toString(),
                            digestAlgorithm: "SHA-256"
                        },
                        dataType: 'native',
                        xhrFields: {
                            responseType: 'arraybuffer'
                        },
                        success: function (data) {
                          saveAs(new Blob([data], {'type': 'application/zip'}), "ers.zip");
                          $form.removeClass('is-uploading');
                          $form.addClass('is-success');
                          $form.find('.dropbox__success').show();
                          $('#trigger-generation').hide();
                          $('#reset-generation').show().css('display', 'inline-block');;
                        },
                        error: function () {
                            handleFormError($form);
                            $('#trigger-generation').hide();
                            $('#reset-generation').show().css('display', 'inline-block');
                        }
                    });
                });
            }
        }
    });
};

let handleFormError = function (form) {

    form.removeClass('is-uploading');
    form.addClass('is-error');
}

let resetFileInput = function (elt) {

    elt.wrap('<form>').closest('form').trigger('reset');
    elt.unwrap();
}

Ers.swapCode = function () {

    $('a.button.code').click(function (e) {
       var me = $(this);
       let divClass = 'div.code.' + $(this).data('code') + ':first';
       me.parent().siblings('div.code.endpoint:first').hide();
       me.parent().siblings('div.code.curl:first').hide();
       me.parent().siblings('div.code.java:first').hide();
       me.parent().siblings('div.code.javascript:first').hide();
       me.parent().siblings(divClass).show();
    });
}

Ers.initResetButtons = function() {

    $('#reset-generation').on('click', function () {
        let $form = $('form.dropbox.generate');
        $form[0].reset();
        $form.removeClass('is-success');
        $form.find('div.dropbox__success').hide();
        $form.find('label').text('Choose one or more files');
        $form.find('div.dropbox__input').show();
        $form.find('div.dropbox__icon').show();
        Ers.initUploadForm();
        $(this).hide();
    });

    $('#reset-validation').on('click', function () {
        let $form = $('form.dropbox-val');
        $form[0].reset();
        $form.removeClass('is-uploading');
        $form.find('div.dropbox__success').hide().html("");
        $form.find('div.dropbox__validation').show();
        $form.find('.dropbox__icon').show();
        $form.find('label[for="ers-validate"]').text('Choose Evidence Record file').show();
        $form.find('label[for="file-validate"]').text('Choose accompanying file').show();
        resetFileInput($('#ers-validate'));
        resetFileInput($('#file-validate'));
        Ers.initValidationForm();
        $(this).hide();
    });
}

Ers.init = function () {

    Ers.initUploadForm();
    Ers.initValidationForm();
    Ers.initResetButtons();
    initButtons();
    Ers.swapCode();
};