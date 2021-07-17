const form = document.forms.student;

const firstname = form.elements.firstname;
const lastname = form.elements.lastname;
const email = form.elements.email;
const phone = form.elements.phone;

let isValid;

let checkFirstName = () => {
    if (firstname.value.trim() == "") {
        isValid = false;
        firstname.classList.add("is-invalid");
    } else {
        firstname.classList.remove("is-invalid");
    }
};

let checkLastName = () => {
    if (lastname.value.trim() == "") {
        isValid = false;
        lastname.classList.add("is-invalid");
    } else {
        lastname.classList.remove("is-invalid");
    }
};

let checkEmail = () => {
    if (email.value.trim() == "" || email.value.indexOf("@") == -1) {
        isValid = false;
        email.classList.add("is-invalid");
    } else {
        email.classList.remove("is-invalid");
    }
};

let checkPhone = () => {
    if (!/[0-9]{10}/.test(phone.value.trim())) {
        isValid = false;
        phone.classList.add("is-invalid");
    } else {
        phone.classList.remove("is-invalid");
    }
};

export default function () {
    isValid = true;

    checkFirstName();
    checkLastName();
    checkEmail();
    checkPhone();

    return isValid
        ? {
              first_name: firstname.value.trim(),
              last_name: lastname.value.trim(),
              email: email.value.trim(),
              phone: phone.value.trim(),
          }
        : null;
}

export { form, firstname, lastname, email, phone };
