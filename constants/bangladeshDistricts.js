/**
 * All 64 districts of Bangladesh (English names).
 * Used as the "approved list" for Gemini to prevent hallucination.
 */
const BANGLADESH_DISTRICTS = [
  // Dhaka Division
  'Dhaka', 'Faridpur', 'Gazipur', 'Gopalganj', 'Kishoreganj', 'Madaripur',
  'Manikganj', 'Munshiganj', 'Narayanganj', 'Narsingdi', 'Rajbari', 'Shariatpur', 'Tangail',
  // Chattogram Division
  'Bandarban', 'Brahmanbaria', 'Chandpur', 'Chattogram', 'Cumilla', 'Coxs Bazar',
  'Feni', 'Khagrachhari', 'Lakshmipur', 'Noakhali', 'Rangamati',
  // Rajshahi Division
  'Bogura', 'Joypurhat', 'Naogaon', 'Natore', 'Chapainawabganj', 'Pabna', 'Rajshahi', 'Sirajganj',
  // Khulna Division
  'Bagerhat', 'Chuadanga', 'Jashore', 'Jhenaidah', 'Khulna', 'Kushtia',
  'Magura', 'Meherpur', 'Narail', 'Satkhira',
  // Barishal Division
  'Barguna', 'Barishal', 'Bhola', 'Jhalokati', 'Patuakhali', 'Pirojpur',
  // Sylhet Division
  'Habiganj', 'Moulvibazar', 'Sunamganj', 'Sylhet',
  // Rangpur Division
  'Dinajpur', 'Gaibandha', 'Kurigram', 'Lalmonirhat', 'Nilphamari',
  'Panchagarh', 'Rangpur', 'Thakurgaon',
  // Mymensingh Division
  'Jamalpur', 'Mymensingh', 'Netrokona', 'Sherpur',
];

module.exports = { BANGLADESH_DISTRICTS };