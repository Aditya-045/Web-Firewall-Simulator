// Simple, explicit translation lookup for the small set of fixed UI labels
// (verdict words + a few static strings). This does NOT require training a
// model -- these are just static UI microcopy, not detection results, so a
// lookup table is the right tool here (this is standard i18n practice, not
// "hardcoding" in the sense the rest of this project avoids -- no scan
// result or confidence number is ever hardcoded, only these fixed labels).
//
// To add a language: add a new key below with the same shape as "en".
// If you'd rather have Claude wire this to a backend/ML translation call
// later, this is the single place that would need to change -- everything
// else in the app just calls t(language, "key").

export const LANGUAGES = [
  { code: "en", label: "English" },
  { code: "hi", label: "हिन्दी (Hindi)" },
  { code: "bn", label: "বাংলা (Bengali)" },
  { code: "ta", label: "தமிழ் (Tamil)" },
  { code: "te", label: "తెలుగు (Telugu)" },
  { code: "mr", label: "मराठी (Marathi)" },
];
//Threat Scanner
//Check a link or message for malicious intent using a trained model, with source lookup and a live feedback loop.
//Scan
//Recent scans
//Result language
const DICT = {
  en: {
    malicious: "Malicious",
    safe: "Safe",
    unknown: "Not sure",
    scan: "Scan",
    scanning: "Scanning...",
    link: "Link",
    textMessage: "Text message",
    confidence: "AI confidence level",
    wasCorrect: "Was this verdict correct?",
    confirmMalicious: "Confirm malicious",
    confirmSafe: "Confirm safe",
    thanks: "Thanks — the model was updated with this confirmed result.",
  },
  hi: {
    malicious: "दुर्भावनापूर्ण",
    safe: "सुरक्षित",
    unknown: "अनिश्चित", //not implemented
    scan: "स्कैन करें",
    scanning: "स्कैन हो रहा है...",
    link: "लिंक",
    textMessage: "टेक्स्ट संदेश",
    confidence: "एआई विश्वास स्तर",
    wasCorrect: "क्या यह निर्णय सही था?",
    confirmMalicious: "दुर्भावनापूर्ण के रूप में पुष्टि करें",
    confirmSafe: "सुरक्षित के रूप में पुष्टि करें",
    thanks: "धन्यवाद — मॉडल को इस पुष्टि किए गए परिणाम से अपडेट किया गया।",
  },
  bn: {
    malicious: "ক্ষতিকারক",
    safe: "নিরাপদ",
    unknown: "অনিশ্চিত",
    scan: "স্ক্যান করুন",
    scanning: "স্ক্যান হচ্ছে...",
    link: "লিঙ্ক",
    textMessage: "টেক্সট বার্তা",
    confidence: "এআই আত্মবিশ্বাসের মাত্রা",
    wasCorrect: "এই রায়টি কি সঠিক ছিল?",
    confirmMalicious: "ক্ষতিকারক নিশ্চিত করুন",
    confirmSafe: "নিরাপদ নিশ্চিত করুন",
    thanks: "ধন্যবাদ — এই নিশ্চিত ফলাফল দিয়ে মডেলটি আপডেট করা হয়েছে।",
  },
  ta: {
    malicious: "தீங்கிழைக்கும்",
    safe: "பாதுகாப்பானது",
    unknown: "உறுதியாக இல்லை",
    scan: "ஸ்கேன் செய்",
    scanning: "ஸ்கேன் செய்யப்படுகிறது...",
    link: "இணைப்பு",
    textMessage: "உரை செய்தி",
    confidence: "AI நம்பிக்கை நிலை",
    wasCorrect: "இந்த முடிவு சரியானதா?",
    confirmMalicious: "தீங்கிழைக்கும் என உறுதிப்படுத்து",
    confirmSafe: "பாதுகாப்பானது என உறுதிப்படுத்து",
    thanks: "நன்றி — இந்த உறுதிப்படுத்தப்பட்ட முடிவுடன் மாதிரி புதுப்பிக்கப்பட்டது.",
  },
  te: {
    malicious: "హానికరమైనది",
    safe: "సురక్షితం",
    unknown: "నిర్ధారణ లేదు",
    scan: "స్కాన్ చేయండి",
    scanning: "స్కాన్ అవుతోంది...",
    link: "లింక్",
    textMessage: "టెక్స్ట్ సందేశం",
    confidence: "AI నమ్మక స్థాయి",
    wasCorrect: "ఈ నిర్ణయం సరైనదేనా?",
    confirmMalicious: "హానికరమైనదిగా నిర్ధారించండి",
    confirmSafe: "సురక్షితంగా నిర్ధారించండి",
    thanks: "ధన్యవాదాలు — ఈ నిర్ధారించిన ఫలితంతో మోడల్ నవీకరించబడింది.",
  },
  mr: {
    malicious: "हानिकारक",
    safe: "सुरक्षित",
    unknown: "अनिश्चित",
    scan: "स्कॅन करा",
    scanning: "स्कॅन होत आहे...",
    link: "दुवा",
    textMessage: "मजकूर संदेश",
    confidence: "एआय आत्मविश्वास पातळी",
    wasCorrect: "हा निकाल बरोबर होता का?",
    confirmMalicious: "हानिकारक असल्याची पुष्टी करा",
    confirmSafe: "सुरक्षित असल्याची पुष्टी करा",
    thanks: "धन्यवाद — मॉडेल या पुष्टी केलेल्या निकालासह अद्ययावत केले गेले.",
  },
};

export function t(language, key) {
  return DICT[language]?.[key] ?? DICT.en[key] ?? key;
}
