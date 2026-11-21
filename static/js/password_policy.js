export const PASSWORD_HELP = 'Use at least 8 characters, including uppercase and lowercase letters, a number, and a special character (for example !, @, or #).';
// Matches Firebase's supported non-alphanumeric characters.
export function validPassword(password) {
  return typeof password === 'string' && password.length >= 8 && password.length <= 4096 &&
    /[A-Z]/.test(password) && /[a-z]/.test(password) && /[0-9]/.test(password) &&
    /[\^$*.\[\]{}()?"!@#%&/\\,><':;|_~]/.test(password);
}
