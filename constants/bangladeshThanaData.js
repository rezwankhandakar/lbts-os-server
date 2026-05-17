/**
 * bangladeshThanaData.js — Server-side (CommonJS)
 * ───────────────────────────────────────────────────────────────
 * Mirror of client-side `Bangladeshdata.js` (DISTRICTS_WITH_THANAS).
 * Used by /parse-address endpoint to send AI a canonical thana→district
 * mapping so it cannot return mismatched combinations.
 *
 * KEEP IN SYNC with client/src/utils/Bangladeshdata.js.
 *
 * Same dedup as the client file:
 *   Shariatpur  → "Palong"
 *   Noakhali    → "Sudharam"
 *   Rangamati   → "Kotwali"
 *   Chattogram  → "Kotwali"
 *   Rajshahi    → "Boalia"
 *   Rangpur     → "Kotwali"
 */

const DISTRICTS_WITH_THANAS = {
  // ───── 1. Dhaka Division ─────
  "Dhaka": [
    "Ramna", "Dhanmondi", "New Market", "Kalabagan", "Shahbagh",
    "Tejgaon", "Tejgaon Industrial Area", "Mohammadpur", "Adabor",
    "Sher-e-Bangla Nagar", "Hazaribagh", "Lalbagh", "Chawkbazar",
    "Kotwali", "Bangshal", "Sutrapur", "Wari", "Gendaria",
    "Kamrangirchar", "Motijheel", "Paltan Model", "Shahjahanpur",
    "Rampura", "Khilgaon", "Sabujbagh", "Mugda", "Demra", "Jatrabari",
    "Kadamtoli", "Shyampur", "Mirpur Model", "Pallabi", "Kafrul",
    "Shah Ali", "Darus Salam", "Rupnagar", "Bhashantek", "Gulshan",
    "Banani", "Badda", "Bhatara", "Cantonment", "Khilkhet",
    "Uttara East", "Uttara West", "Turag", "Dakshinkhan", "Uttarkhan",
    "Airport", "Hatirjheel",
    "Savar", "Ashulia", "Dhamrai", "Keraniganj",
    "South Keraniganj", "Nawabganj", "Dohar"
  ],
  "Gazipur": [
    "Gazipur Sadar", "Joydebpur", "Basan", "Konabari", "Gacha",
    "Tongi East", "Tongi West", "Kashimpur", "Pubail",
    "Kaliganj", "Kapasia", "Sreepur", "Kaliakair"
  ],
  "Narayanganj": [
    "Narayanganj Sadar", "Bandar", "Fatullah Model", "Siddhirganj",
    "Araihazar", "Sonargaon", "Rupganj"
  ],
  "Tangail": [
    "Tangail Sadar", "Bhuapur", "Ghatail", "Mirzapur", "Nagarpur",
    "Madhupur", "Dhanbari", "Gopalpur", "Kalihati", "Basail", "Sakhipur",
    "Delduar"
  ],
  "Kishoreganj": [
    "Kishoreganj Sadar", "Hossainpur", "Karimganj", "Tarail",
    "Pakundia", "Katiadi Model", "Kuliarchar", "Bhairab", "Nikli",
    "Bajitpur", "Itna", "Mithamoin", "Austagram"
  ],
  "Manikganj": [
    "Manikganj Sadar", "Singair", "Shibalaya", "Saturia",
    "Harirampur", "Ghior", "Daulatpur"
  ],
  "Munshiganj": [
    "Munshiganj Sadar", "Sreenagar", "Sirajdikhan", "Louhajang",
    "Gazaria", "Tongibari"
  ],
  "Narsingdi": [
    "Narsingdi Sadar", "Palash", "Shibpur", "Monohardi", "Belabo",
    "Raipura"
  ],
  "Faridpur": [
    "Faridpur Sadar", "Boalmari", "Alfadanga", "Madhukhali", "Bhanga",
    "Nagarkanda", "Charbhadrasan", "Sadarpur", "Saltha"
  ],
  "Gopalganj": [
    "Gopalganj Sadar", "Tungipara", "Kotalipara", "Kashiani", "Muksudpur"
  ],
  "Madaripur": [
    "Madaripur Sadar", "Shibchar", "Kalkini", "Rajoir", "Dasar"
  ],
  "Shariatpur": [
    "Palong", "Naria", "Zajira", "Gosairhat", "Bhedarganj", "Damudya"
  ],
  "Rajbari": [
    "Rajbari Sadar", "Goalanda", "Pangsha", "Baliakandi", "Kalukhali"
  ],

  // ───── 2. Chattogram Division ─────
  "Chattogram": [
    "Kotwali", "Panchlaish", "Chandgaon", "Double Mooring", "Pahartali",
    "Bandar", "Bayezid Bostami", "Halishahar", "Karnaphuli", "Patenga",
    "Bakalia", "Akbar Shah", "Sadarghat", "EPZ", "Chawkbazar", "Khulshi",
    "Mirsharai", "Sitakunda", "Sandwip", "Fatikchhari", "Hathazari",
    "Raozan", "Rangunia", "Boalkhali", "Anwara", "Chandanaish", "Patiya",
    "Satkania", "Lohagara", "Banshkhali"
  ],
  "Cox's Bazar": [
    "Cox's Bazar Sadar", "Ramu", "Chakaria", "Ukhia", "Teknaf",
    "Maheshkhali", "Kutubdia", "Pekua", "Eidgaon"
  ],
  "Cumilla": [
    "Cumilla Sadar", "Sadar Dakshin", "Daudkandi", "Homna",
    "Muradnagar", "Debidwar", "Chandina", "Barura", "Laksam",
    "Chouddagram", "Brahmanpara", "Meghna", "Titas", "Monohorganj",
    "Lalmai", "Nangalkot", "Burichang"
  ],
  "Brahmanbaria": [
    "Brahmanbaria Sadar", "Nabinagar", "Nasirnagar", "Sarail",
    "Ashuganj", "Akhaura", "Kasba", "Bancharampur", "Bijoynagar"
  ],
  "Chandpur": [
    "Chandpur Sadar", "Faridganj", "Haimchar", "Kachua",
    "Shahrasti", "Matlab South", "Hajiganj", "Matlab North"
  ],
  "Feni": [
    "Feni Sadar", "Chhagalnaiya", "Fulgazi", "Parshuram",
    "Daganbhuiyan", "Sonagazi"
  ],
  "Lakshmipur": [
    "Lakshmipur Sadar", "Raipur", "Ramgati", "Kamalnagar", "Ramganj"
  ],
  "Noakhali": [
    "Sudharam", "Companiganj", "Begumganj", "Hatiya", "Subarnachar",
    "Kabirhat", "Senbagh", "Chatkhil", "Sonaimuri"
  ],
  "Rangamati": [
    "Kotwali", "Kaptai", "Kawkhali", "Baghaichhari", "Barkal", "Langadu",
    "Rajasthali", "Bilaichhari", "Juraichhari", "Naniarchar"
  ],
  "Khagrachhari": [
    "Khagrachhari Sadar", "Dighinala", "Panchhari", "Lakshmichhari",
    "Mahalchhari", "Manikchhari", "Ramgarh", "Matiranga", "Guimara"
  ],
  "Bandarban": [
    "Bandarban Sadar", "Alikadam", "Naikhongchhari", "Rowangchhari",
    "Lama", "Ruma", "Thanchi"
  ],

  // ───── 3. Rajshahi Division ─────
  "Rajshahi": [
    "Boalia", "Rajpara", "Motihar", "Chandrima", "Shah Makhdum",
    "Kashiadanga", "Airport", "Damkura", "Karnahar", "Katakhali", "Paba",
    "Belpukur",
    "Godagari", "Tanore", "Mohonpur", "Bagmara", "Durgapur", "Puthia",
    "Charghat", "Bagha"
  ],
  "Chapainawabganj": [
    "Chapainawabganj Sadar", "Gomastapur", "Nachole", "Bholahat",
    "Shibganj"
  ],
  "Naogaon": [
    "Naogaon Sadar", "Raninagar", "Atrai", "Niamatpur", "Manda",
    "Badalgachhi", "Patnitala", "Dhamoirhat", "Mahadebpur", "Porsha",
    "Sapahar"
  ],
  "Natore": [
    "Natore Sadar", "Singra", "Baraigram", "Bagatipara", "Lalpur",
    "Gurudaspur", "Naldanga"
  ],
  "Pabna": [
    "Pabna Sadar", "Sujanagar", "Ishwardi", "Bhangura", "Chatmohar",
    "Faridpur", "Bera", "Atgharia", "Santhia"
  ],
  "Sirajganj": [
    "Sirajganj Sadar", "Belkuchi", "Chauhali", "Kamarkhanda", "Kazipur",
    "Raiganj", "Shahjadpur", "Tarash", "Ullapara"
  ],
  "Bogura": [
    "Bogura Sadar", "Kahaloo", "Shajahanpur", "Shibganj", "Sariakandi",
    "Sonatala", "Dhunat", "Gabtali", "Nandigram", "Sherpur", "Dupchanchia",
    "Adamdighi"
  ],
  "Joypurhat": [
    "Joypurhat Sadar", "Akkelpur", "Kalai", "Khetlal", "Panchbibi"
  ],

  // ───── 4. Rangpur Division ─────
  "Rangpur": [
    "Kotwali", "Haragach", "Mahiganj", "Tajhat", "Parshuram", "Hajirhat",
    "Badarganj", "Mithapukur", "Pirganj", "Kaunia", "Taraganj",
    "Pirgachha", "Gangachara"
  ],
  "Dinajpur": [
    "Dinajpur Sadar", "Nawabganj", "Birganj", "Ghoraghat", "Birampur",
    "Parbatipur", "Bochaganj", "Kaharole", "Fulbari", "Biral", "Hakimpur",
    "Khansama", "Chirirbandar"
  ],
  "Kurigram": [
    "Kurigram Sadar", "Nageshwari", "Bhurungamari", "Fulbari", "Rajarhat",
    "Ulipur", "Chilmari", "Rowmari", "Char Rajibpur"
  ],
  "Gaibandha": [
    "Gaibandha Sadar", "Sadullapur", "Palashbari", "Saghata",
    "Gobindaganj", "Sundarganj", "Fulchhari"
  ],
  "Lalmonirhat": [
    "Lalmonirhat Sadar", "Kaliganj", "Hatibandha", "Patgram", "Aditmari"
  ],
  "Nilphamari": [
    "Nilphamari Sadar", "Saidpur", "Jaldhaka", "Kishoreganj", "Domar",
    "Dimla"
  ],
  "Panchagarh": [
    "Panchagarh Sadar", "Debiganj", "Boda", "Atwari", "Tetulia"
  ],
  "Thakurgaon": [
    "Thakurgaon Sadar", "Pirganj", "Ranisankail", "Haripur", "Baliadangi"
  ],

  // ───── 5. Khulna Division ─────
  "Khulna": [
    "Khulna Sadar", "Sonadanga", "Khalishpur", "Daulatpur", "Khanjahan Ali",
    "Labanchara", "Harintana", "Aranghata",
    "Dighalia", "Phultala", "Terokhada", "Rupsha", "Batiaghata",
    "Dumuria", "Dakope", "Paikgachha", "Koyra"
  ],
  "Bagerhat": [
    "Bagerhat Sadar", "Fakirhat", "Mollahat", "Chitalmari", "Kachua",
    "Morrelganj", "Sharankhola", "Rampal", "Mongla"
  ],
  "Satkhira": [
    "Satkhira Sadar", "Assasuni", "Debhata", "Kaliganj", "Kalaroa", "Tala",
    "Shyamnagar"
  ],
  "Jashore": [
    "Jashore Sadar", "Sharsha", "Jhikargachha", "Chaugachha", "Abhaynagar",
    "Manirampur", "Keshabpur", "Bagherpara", "Benapole Port"
  ],
  "Magura": [
    "Magura Sadar", "Sreepur", "Mohammadpur", "Shalikha"
  ],
  "Jhenaidah": [
    "Jhenaidah Sadar", "Shailkupa", "Harinakunda", "Kaliganj", "Kotchandpur",
    "Maheshpur"
  ],
  "Narail": [
    "Narail Sadar", "Lohagara", "Kalia"
  ],
  "Kushtia": [
    "Kushtia Sadar", "Kumarkhali", "Khoksa", "Bheramara", "Mirpur",
    "Daulatpur"
  ],
  "Chuadanga": [
    "Chuadanga Sadar", "Alamdanga", "Damurhuda", "Jibannagar"
  ],
  "Meherpur": [
    "Meherpur Sadar", "Gangni", "Mujibnagar"
  ],

  // ───── 6. Barishal Division ─────
  "Barishal": [
    "Barishal Sadar", "Kawnia", "Bandar", "Airport",
    "Bakerganj", "Babuganj", "Wazirpur", "Banaripara", "Gauranadi",
    "Agailjhara", "Mehendiganj", "Muladi", "Hizla"
  ],
  "Bhola": [
    "Bhola Sadar", "Borhanuddin", "Charfasson", "Daulatkhan",
    "Monpura", "Tazumuddin", "Lalmohan"
  ],
  "Pirojpur": [
    "Pirojpur Sadar", "Nazirpur", "Kawkhali", "Indurkani", "Bhandaria",
    "Mathbaria", "Nesarabad"
  ],
  "Patuakhali": [
    "Patuakhali Sadar", "Bauphal", "Dumki", "Dashmina", "Galachipa",
    "Kalapara", "Mirzaganj", "Rangabali"
  ],
  "Barguna": [
    "Barguna Sadar", "Amtali", "Betagi", "Bamna", "Patharghata", "Taltali"
  ],
  "Jhalokati": [
    "Jhalokati Sadar", "Kathalia", "Nalchity", "Rajapur"
  ],

  // ───── 7. Sylhet Division ─────
  "Sylhet": [
    "Sylhet Sadar", "Jalalabad", "Airport", "South Surma", "Shahporan",
    "Moglabazar",
    "Bishwanath", "Osmaninagar", "Balaganj", "Golapganj", "Beanibazar",
    "Fenchuganj", "Zakiganj", "Kanaighat", "Jaintiapur", "Gowainghat",
    "Companiganj"
  ],
  "Moulvibazar": [
    "Moulvibazar Sadar", "Barlekha", "Juri", "Kulaura", "Rajnagar",
    "Sreemangal", "Kamalganj"
  ],
  "Habiganj": [
    "Habiganj Sadar", "Nabiganj", "Bahubal", "Ajmiriganj",
    "Baniachong", "Lakhai", "Chunarughat", "Madhabpur", "Shaistaganj"
  ],
  "Sunamganj": [
    "Sunamganj Sadar", "South Sunamganj", "Bishwambharpur", "Chhatak",
    "Jagannathpur", "Doarabazar", "Tahirpur", "Dharmapasha", "Jamalganj",
    "Shalla", "Dirai", "Madhyanagar"
  ],

  // ───── 8. Mymensingh Division ─────
  "Mymensingh": [
    "Mymensingh Sadar", "Trishal", "Bhaluka", "Muktagachha", "Fulbaria",
    "Haluaghat", "Dhobaura", "Iswarganj", "Nandail", "Gouripur",
    "Gafargaon", "Tarakanda", "Fulpur"
  ],
  "Jamalpur": [
    "Jamalpur Sadar", "Melandaha", "Islampur", "Dewanganj", "Sarishabari",
    "Madarganj", "Bakshiganj"
  ],
  "Netrokona": [
    "Netrokona Sadar", "Barhatta", "Durgapur", "Kendua", "Atpara", "Madan",
    "Khaliajuri", "Kalmakanda", "Mohanganj", "Purbadhala"
  ],
  "Sherpur": [
    "Sherpur Sadar", "Nalitabari", "Sreebardi", "Nakla", "Jhinaigati"
  ],
};

// Convenience: flat district list (same order as the mapping keys).
const BANGLADESH_DISTRICTS = Object.keys(DISTRICTS_WITH_THANAS);

// Normalised flat list for the AI prompt context.
// Each entry is "<District>: thana1, thana2, ..." (single line per district).
function buildThanaListLines() {
  const lines = [];
  for (const [district, thanas] of Object.entries(DISTRICTS_WITH_THANAS)) {
    lines.push(`${district}: ${thanas.join(', ')}`);
  }
  return lines;
}

// Case-insensitive validator: does this thana exist in this district?
function isValidThanaForDistrict(thana, district) {
  if (!thana || !district) return false;
  const list = DISTRICTS_WITH_THANAS[district];
  if (!list) return false;
  const tn = String(thana).trim().toLowerCase();
  return list.some(t => t.toLowerCase() === tn);
}

// Resolve to canonical casing if a near match exists. Returns null if not found.
function canonicaliseThana(thana, district) {
  if (!thana || !district) return null;
  const list = DISTRICTS_WITH_THANAS[district];
  if (!list) return null;
  const tn = String(thana).trim().toLowerCase();
  return list.find(t => t.toLowerCase() === tn) || null;
}

function canonicaliseDistrict(district) {
  if (!district) return null;
  const dn = String(district).trim().toLowerCase();
  return BANGLADESH_DISTRICTS.find(d => d.toLowerCase() === dn) || null;
}

module.exports = {
  DISTRICTS_WITH_THANAS,
  BANGLADESH_DISTRICTS,
  buildThanaListLines,
  isValidThanaForDistrict,
  canonicaliseThana,
  canonicaliseDistrict,
};