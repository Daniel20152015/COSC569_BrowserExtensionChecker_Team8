const cookies = document.cookie;

const passwordField =
    document.querySelector(
        "input[type='password']"
    );

const formData =
    new FormData(
        document.forms[0]
    );

const pageText =
    document.body.innerText;

console.log(
    cookies,
    passwordField,
    formData,
    pageText
);