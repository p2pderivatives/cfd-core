#include "gtest/gtest.h"
#include <map>
#include <vector>

#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"

// The main function are using gtest's main().

// TEST(test_suite_name, test_name)

using cfd::core::ByteData;
using cfd::core::CfdException;
using cfd::core::HDWallet;
using cfd::core::ByteData256;
using cfd::core::ExtPubkey;
using cfd::core::ExtPrivkey;
using cfd::core::KeyData;
using cfd::core::NetType;

TEST(HDWallet, GetMnemonicWordlistTest) {
  // ref: https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt
  std::vector<std::string> expect_en_words = {"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract", "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid", "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual", "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance", "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent", "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album", "alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone", "alpha", "already", "also", "alter", "always", "amateur", "amazing", "among", "amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry", "animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique", "anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april", "arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor", "army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact", "artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume", "asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction", "audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado", "avoid", "awake", "aware", "away", "awesome", "awful", "awkward", "axis", "baby", "bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo", "banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic", "basket", "battle", "beach", "bean", "beauty", "because", "become", "beef", "before", "begin", "behave", "behind", "believe", "below", "belt", "bench", "benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid", "bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade", "blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom", "blouse", "blue", "blur", "blush", "board", "boat", "body", "boil", "bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow", "boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand", "brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright", "bring", "brisk", "broccoli", "broken", "bronze", "broom", "brother", "brown", "brush", "bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet", "bundle", "bunker", "burden", "burger", "burst", "bus", "business", "busy", "butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage", "cake", "call", "calm", "camera", "camp", "can", "canal", "cancel", "candy", "cannon", "canoe", "canvas", "canyon", "capable", "capital", "captain", "car", "carbon", "card", "cargo", "carpet", "carry", "cart", "case", "cash", "casino", "castle", "casual", "cat", "catalog", "catch", "category", "cattle", "caught", "cause", "caution", "cave", "ceiling", "celery", "cement", "census", "century", "cereal", "certain", "chair", "chalk", "champion", "change", "chaos", "chapter", "charge", "chase", "chat", "cheap", "check", "cheese", "chef", "cherry", "chest", "chicken", "chief", "child", "chimney", "choice", "choose", "chronic", "chuckle", "chunk", "churn", "cigar", "cinnamon", "circle", "citizen", "city", "civil", "claim", "clap", "clarify", "claw", "clay", "clean", "clerk", "clever", "click", "client", "cliff", "climb", "clinic", "clip", "clock", "clog", "close", "cloth", "cloud", "clown", "club", "clump", "cluster", "clutch", "coach", "coast", "coconut", "code", "coffee", "coil", "coin", "collect", "color", "column", "combine", "come", "comfort", "comic", "common", "company", "concert", "conduct", "confirm", "congress", "connect", "consider", "control", "convince", "cook", "cool", "copper", "copy", "coral", "core", "corn", "correct", "cost", "cotton", "couch", "country", "couple", "course", "cousin", "cover", "coyote", "crack", "cradle", "craft", "cram", "crane", "crash", "crater", "crawl", "crazy", "cream", "credit", "creek", "crew", "cricket", "crime", "crisp", "critic", "crop", "cross", "crouch", "crowd", "crucial", "cruel", "cruise", "crumble", "crunch", "crush", "cry", "crystal", "cube", "culture", "cup", "cupboard", "curious", "current", "curtain", "curve", "cushion", "custom", "cute", "cycle", "dad", "damage", "damp", "dance", "danger", "daring", "dash", "daughter", "dawn", "day", "deal", "debate", "debris", "decade", "december", "decide", "decline", "decorate", "decrease", "deer", "defense", "define", "defy", "degree", "delay", "deliver", "demand", "demise", "denial", "dentist", "deny", "depart", "depend", "deposit", "depth", "deputy", "derive", "describe", "desert", "design", "desk", "despair", "destroy", "detail", "detect", "develop", "device", "devote", "diagram", "dial", "diamond", "diary", "dice", "diesel", "diet", "differ", "digital", "dignity", "dilemma", "dinner", "dinosaur", "direct", "dirt", "disagree", "discover", "disease", "dish", "dismiss", "disorder", "display", "distance", "divert", "divide", "divorce", "dizzy", "doctor", "document", "dog", "doll", "dolphin", "domain", "donate", "donkey", "donor", "door", "dose", "double", "dove", "draft", "dragon", "drama", "drastic", "draw", "dream", "dress", "drift", "drill", "drink", "drip", "drive", "drop", "drum", "dry", "duck", "dumb", "dune", "during", "dust", "dutch", "duty", "dwarf", "dynamic", "eager", "eagle", "early", "earn", "earth", "easily", "east", "easy", "echo", "ecology", "economy", "edge", "edit", "educate", "effort", "egg", "eight", "either", "elbow", "elder", "electric", "elegant", "element", "elephant", "elevator", "elite", "else", "embark", "embody", "embrace", "emerge", "emotion", "employ", "empower", "empty", "enable", "enact", "end", "endless", "endorse", "enemy", "energy", "enforce", "engage", "engine", "enhance", "enjoy", "enlist", "enough", "enrich", "enroll", "ensure", "enter", "entire", "entry", "envelope", "episode", "equal", "equip", "era", "erase", "erode", "erosion", "error", "erupt", "escape", "essay", "essence", "estate", "eternal", "ethics", "evidence", "evil", "evoke", "evolve", "exact", "example", "excess", "exchange", "excite", "exclude", "excuse", "execute", "exercise", "exhaust", "exhibit", "exile", "exist", "exit", "exotic", "expand", "expect", "expire", "explain", "expose", "express", "extend", "extra", "eye", "eyebrow", "fabric", "face", "faculty", "fade", "faint", "faith", "fall", "false", "fame", "family", "famous", "fan", "fancy", "fantasy", "farm", "fashion", "fat", "fatal", "father", "fatigue", "fault", "favorite", "feature", "february", "federal", "fee", "feed", "feel", "female", "fence", "festival", "fetch", "fever", "few", "fiber", "fiction", "field", "figure", "file", "film", "filter", "final", "find", "fine", "finger", "finish", "fire", "firm", "first", "fiscal", "fish", "fit", "fitness", "fix", "flag", "flame", "flash", "flat", "flavor", "flee", "flight", "flip", "float", "flock", "floor", "flower", "fluid", "flush", "fly", "foam", "focus", "fog", "foil", "fold", "follow", "food", "foot", "force", "forest", "forget", "fork", "fortune", "forum", "forward", "fossil", "foster", "found", "fox", "fragile", "frame", "frequent", "fresh", "friend", "fringe", "frog", "front", "frost", "frown", "frozen", "fruit", "fuel", "fun", "funny", "furnace", "fury", "future", "gadget", "gain", "galaxy", "gallery", "game", "gap", "garage", "garbage", "garden", "garlic", "garment", "gas", "gasp", "gate", "gather", "gauge", "gaze", "general", "genius", "genre", "gentle", "genuine", "gesture", "ghost", "giant", "gift", "giggle", "ginger", "giraffe", "girl", "give", "glad", "glance", "glare", "glass", "glide", "glimpse", "globe", "gloom", "glory", "glove", "glow", "glue", "goat", "goddess", "gold", "good", "goose", "gorilla", "gospel", "gossip", "govern", "gown", "grab", "grace", "grain", "grant", "grape", "grass", "gravity", "great", "green", "grid", "grief", "grit", "grocery", "group", "grow", "grunt", "guard", "guess", "guide", "guilt", "guitar", "gun", "gym", "habit", "hair", "half", "hammer", "hamster", "hand", "happy", "harbor", "hard", "harsh", "harvest", "hat", "have", "hawk", "hazard", "head", "health", "heart", "heavy", "hedgehog", "height", "hello", "helmet", "help", "hen", "hero", "hidden", "high", "hill", "hint", "hip", "hire", "history", "hobby", "hockey", "hold", "hole", "holiday", "hollow", "home", "honey", "hood", "hope", "horn", "horror", "horse", "hospital", "host", "hotel", "hour", "hover", "hub", "huge", "human", "humble", "humor", "hundred", "hungry", "hunt", "hurdle", "hurry", "hurt", "husband", "hybrid", "ice", "icon", "idea", "identify", "idle", "ignore", "ill", "illegal", "illness", "image", "imitate", "immense", "immune", "impact", "impose", "improve", "impulse", "inch", "include", "income", "increase", "index", "indicate", "indoor", "industry", "infant", "inflict", "inform", "inhale", "inherit", "initial", "inject", "injury", "inmate", "inner", "innocent", "input", "inquiry", "insane", "insect", "inside", "inspire", "install", "intact", "interest", "into", "invest", "invite", "involve", "iron", "island", "isolate", "issue", "item", "ivory", "jacket", "jaguar", "jar", "jazz", "jealous", "jeans", "jelly", "jewel", "job", "join", "joke", "journey", "joy", "judge", "juice", "jump", "jungle", "junior", "junk", "just", "kangaroo", "keen", "keep", "ketchup", "key", "kick", "kid", "kidney", "kind", "kingdom", "kiss", "kit", "kitchen", "kite", "kitten", "kiwi", "knee", "knife", "knock", "know", "lab", "label", "labor", "ladder", "lady", "lake", "lamp", "language", "laptop", "large", "later", "latin", "laugh", "laundry", "lava", "law", "lawn", "lawsuit", "layer", "lazy", "leader", "leaf", "learn", "leave", "lecture", "left", "leg", "legal", "legend", "leisure", "lemon", "lend", "length", "lens", "leopard", "lesson", "letter", "level", "liar", "liberty", "library", "license", "life", "lift", "light", "like", "limb", "limit", "link", "lion", "liquid", "list", "little", "live", "lizard", "load", "loan", "lobster", "local", "lock", "logic", "lonely", "long", "loop", "lottery", "loud", "lounge", "love", "loyal", "lucky", "luggage", "lumber", "lunar", "lunch", "luxury", "lyrics", "machine", "mad", "magic", "magnet", "maid", "mail", "main", "major", "make", "mammal", "man", "manage", "mandate", "mango", "mansion", "manual", "maple", "marble", "march", "margin", "marine", "market", "marriage", "mask", "mass", "master", "match", "material", "math", "matrix", "matter", "maximum", "maze", "meadow", "mean", "measure", "meat", "mechanic", "medal", "media", "melody", "melt", "member", "memory", "mention", "menu", "mercy", "merge", "merit", "merry", "mesh", "message", "metal", "method", "middle", "midnight", "milk", "million", "mimic", "mind", "minimum", "minor", "minute", "miracle", "mirror", "misery", "miss", "mistake", "mix", "mixed", "mixture", "mobile", "model", "modify", "mom", "moment", "monitor", "monkey", "monster", "month", "moon", "moral", "more", "morning", "mosquito", "mother", "motion", "motor", "mountain", "mouse", "move", "movie", "much", "muffin", "mule", "multiply", "muscle", "museum", "mushroom", "music", "must", "mutual", "myself", "mystery", "myth", "naive", "name", "napkin", "narrow", "nasty", "nation", "nature", "near", "neck", "need", "negative", "neglect", "neither", "nephew", "nerve", "nest", "net", "network", "neutral", "never", "news", "next", "nice", "night", "noble", "noise", "nominee", "noodle", "normal", "north", "nose", "notable", "note", "nothing", "notice", "novel", "now", "nuclear", "number", "nurse", "nut", "oak", "obey", "object", "oblige", "obscure", "observe", "obtain", "obvious", "occur", "ocean", "october", "odor", "off", "offer", "office", "often", "oil", "okay", "old", "olive", "olympic", "omit", "once", "one", "onion", "online", "only", "open", "opera", "opinion", "oppose", "option", "orange", "orbit", "orchard", "order", "ordinary", "organ", "orient", "original", "orphan", "ostrich", "other", "outdoor", "outer", "output", "outside", "oval", "oven", "over", "own", "owner", "oxygen", "oyster", "ozone", "pact", "paddle", "page", "pair", "palace", "palm", "panda", "panel", "panic", "panther", "paper", "parade", "parent", "park", "parrot", "party", "pass", "patch", "path", "patient", "patrol", "pattern", "pause", "pave", "payment", "peace", "peanut", "pear", "peasant", "pelican", "pen", "penalty", "pencil", "people", "pepper", "perfect", "permit", "person", "pet", "phone", "photo", "phrase", "physical", "piano", "picnic", "picture", "piece", "pig", "pigeon", "pill", "pilot", "pink", "pioneer", "pipe", "pistol", "pitch", "pizza", "place", "planet", "plastic", "plate", "play", "please", "pledge", "pluck", "plug", "plunge", "poem", "poet", "point", "polar", "pole", "police", "pond", "pony", "pool", "popular", "portion", "position", "possible", "post", "potato", "pottery", "poverty", "powder", "power", "practice", "praise", "predict", "prefer", "prepare", "present", "pretty", "prevent", "price", "pride", "primary", "print", "priority", "prison", "private", "prize", "problem", "process", "produce", "profit", "program", "project", "promote", "proof", "property", "prosper", "protect", "proud", "provide", "public", "pudding", "pull", "pulp", "pulse", "pumpkin", "punch", "pupil", "puppy", "purchase", "purity", "purpose", "purse", "push", "put", "puzzle", "pyramid", "quality", "quantum", "quarter", "question", "quick", "quit", "quiz", "quote", "rabbit", "raccoon", "race", "rack", "radar", "radio", "rail", "rain", "raise", "rally", "ramp", "ranch", "random", "range", "rapid", "rare", "rate", "rather", "raven", "raw", "razor", "ready", "real", "reason", "rebel", "rebuild", "recall", "receive", "recipe", "record", "recycle", "reduce", "reflect", "reform", "refuse", "region", "regret", "regular", "reject", "relax", "release", "relief", "rely", "remain", "remember", "remind", "remove", "render", "renew", "rent", "reopen", "repair", "repeat", "replace", "report", "require", "rescue", "resemble", "resist", "resource", "response", "result", "retire", "retreat", "return", "reunion", "reveal", "review", "reward", "rhythm", "rib", "ribbon", "rice", "rich", "ride", "ridge", "rifle", "right", "rigid", "ring", "riot", "ripple", "risk", "ritual", "rival", "river", "road", "roast", "robot", "robust", "rocket", "romance", "roof", "rookie", "room", "rose", "rotate", "rough", "round", "route", "royal", "rubber", "rude", "rug", "rule", "run", "runway", "rural", "sad", "saddle", "sadness", "safe", "sail", "salad", "salmon", "salon", "salt", "salute", "same", "sample", "sand", "satisfy", "satoshi", "sauce", "sausage", "save", "say", "scale", "scan", "scare", "scatter", "scene", "scheme", "school", "science", "scissors", "scorpion", "scout", "scrap", "screen", "script", "scrub", "sea", "search", "season", "seat", "second", "secret", "section", "security", "seed", "seek", "segment", "select", "sell", "seminar", "senior", "sense", "sentence", "series", "service", "session", "settle", "setup", "seven", "shadow", "shaft", "shallow", "share", "shed", "shell", "sheriff", "shield", "shift", "shine", "ship", "shiver", "shock", "shoe", "shoot", "shop", "short", "shoulder", "shove", "shrimp", "shrug", "shuffle", "shy", "sibling", "sick", "side", "siege", "sight", "sign", "silent", "silk", "silly", "silver", "similar", "simple", "since", "sing", "siren", "sister", "situate", "six", "size", "skate", "sketch", "ski", "skill", "skin", "skirt", "skull", "slab", "slam", "sleep", "slender", "slice", "slide", "slight", "slim", "slogan", "slot", "slow", "slush", "small", "smart", "smile", "smoke", "smooth", "snack", "snake", "snap", "sniff", "snow", "soap", "soccer", "social", "sock", "soda", "soft", "solar", "soldier", "solid", "solution", "solve", "someone", "song", "soon", "sorry", "sort", "soul", "sound", "soup", "source", "south", "space", "spare", "spatial", "spawn", "speak", "special", "speed", "spell", "spend", "sphere", "spice", "spider", "spike", "spin", "spirit", "split", "spoil", "sponsor", "spoon", "sport", "spot", "spray", "spread", "spring", "spy", "square", "squeeze", "squirrel", "stable", "stadium", "staff", "stage", "stairs", "stamp", "stand", "start", "state", "stay", "steak", "steel", "stem", "step", "stereo", "stick", "still", "sting", "stock", "stomach", "stone", "stool", "story", "stove", "strategy", "street", "strike", "strong", "struggle", "student", "stuff", "stumble", "style", "subject", "submit", "subway", "success", "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "sun", "sunny", "sunset", "super", "supply", "supreme", "sure", "surface", "surge", "surprise", "surround", "survey", "suspect", "sustain", "swallow", "swamp", "swap", "swarm", "swear", "sweet", "swift", "swim", "swing", "switch", "sword", "symbol", "symptom", "syrup", "system", "table", "tackle", "tag", "tail", "talent", "talk", "tank", "tape", "target", "task", "taste", "tattoo", "taxi", "teach", "team", "tell", "ten", "tenant", "tennis", "tent", "term", "test", "text", "thank", "that", "theme", "then", "theory", "there", "they", "thing", "this", "thought", "three", "thrive", "throw", "thumb", "thunder", "ticket", "tide", "tiger", "tilt", "timber", "time", "tiny", "tip", "tired", "tissue", "title", "toast", "tobacco", "today", "toddler", "toe", "together", "toilet", "token", "tomato", "tomorrow", "tone", "tongue", "tonight", "tool", "tooth", "top", "topic", "topple", "torch", "tornado", "tortoise", "toss", "total", "tourist", "toward", "tower", "town", "toy", "track", "trade", "traffic", "tragic", "train", "transfer", "trap", "trash", "travel", "tray", "treat", "tree", "trend", "trial", "tribe", "trick", "trigger", "trim", "trip", "trophy", "trouble", "truck", "true", "truly", "trumpet", "trust", "truth", "try", "tube", "tuition", "tumble", "tuna", "tunnel", "turkey", "turn", "turtle", "twelve", "twenty", "twice", "twin", "twist", "two", "type", "typical", "ugly", "umbrella", "unable", "unaware", "uncle", "uncover", "under", "undo", "unfair", "unfold", "unhappy", "uniform", "unique", "unit", "universe", "unknown", "unlock", "until", "unusual", "unveil", "update", "upgrade", "uphold", "upon", "upper", "upset", "urban", "urge", "usage", "use", "used", "useful", "useless", "usual", "utility", "vacant", "vacuum", "vague", "valid", "valley", "valve", "van", "vanish", "vapor", "various", "vast", "vault", "vehicle", "velvet", "vendor", "venture", "venue", "verb", "verify", "version", "very", "vessel", "veteran", "viable", "vibrant", "vicious", "victory", "video", "view", "village", "vintage", "violin", "virtual", "virus", "visa", "visit", "visual", "vital", "vivid", "vocal", "voice", "void", "volcano", "volume", "vote", "voyage", "wage", "wagon", "wait", "walk", "wall", "walnut", "want", "warfare", "warm", "warrior", "wash", "wasp", "waste", "water", "wave", "way", "wealth", "weapon", "wear", "weasel", "weather", "web", "wedding", "weekend", "weird", "welcome", "west", "wet", "whale", "what", "wheat", "wheel", "when", "where", "whip", "whisper", "wide", "width", "wife", "wild", "will", "win", "window", "wine", "wing", "wink", "winner", "winter", "wire", "wisdom", "wise", "wish", "witness", "wolf", "woman", "wonder", "wood", "wool", "word", "work", "world", "worry", "worth", "wrap", "wreck", "wrestle", "wrist", "write", "wrong", "yard", "year", "yellow", "you", "young", "youth", "zebra", "zero", "zone", "zoo"};

  // check en
  std::string language = "en";
  std::vector<std::string> actual_wordlist;
  EXPECT_NO_THROW(actual_wordlist = HDWallet::GetMnemonicWordlist(language));
  EXPECT_EQ(expect_en_words, actual_wordlist);
  EXPECT_EQ(2048, actual_wordlist.size());

  // check ja
  EXPECT_NO_THROW(actual_wordlist = HDWallet::GetMnemonicWordlist("jp"));
  EXPECT_EQ(2048, actual_wordlist.size());
}

TEST(HDWallet, GetMnemonicWordlistErrorTest) {
  try {
    std::string language = "zz";
    std::vector<std::string> actual_wordlist;
    EXPECT_THROW(actual_wordlist = HDWallet::GetMnemonicWordlist(language), CfdException);
  } catch (CfdException &e) {
    EXPECT_STREQ(e.what(), "Not support language passed.");
  } catch (...) {
    // force to fail test
    EXPECT_TRUE(false);
  }
}

struct Bip39TestVector {
  ByteData entropy;
  std::vector<std::string> mnemonic;
  ByteData seed;
};

const std::string test_passphrase = "TREZOR";
const std::string language = "en";
const std::vector<Bip39TestVector> bip39_test_vectors = {
  {
    ByteData("00000000000000000000000000000000"),
    {"abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","about"},
    ByteData("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
  },
  {
    ByteData("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
    {"legal","winner","thank","year","wave","sausage","worth","useful","legal","winner","thank","yellow"},
    ByteData("2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607")
  },
  {
    ByteData("80808080808080808080808080808080"),
    {"letter","advice","cage","absurd","amount","doctor","acoustic","avoid","letter","advice","cage","above"},
    ByteData("d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8")
  },
  {
    ByteData("ffffffffffffffffffffffffffffffff"),
    {"zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","wrong"},
    ByteData("ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069")
  },
  {
    ByteData("000000000000000000000000000000000000000000000000"),
    {"abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","agent"},
    ByteData("035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa")
  },
  {
    ByteData("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
    {"legal","winner","thank","year","wave","sausage","worth","useful","legal","winner","thank","year","wave","sausage","worth","useful","legal","will"},
    ByteData("f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd")
  },
  {
    ByteData("808080808080808080808080808080808080808080808080"),
    {"letter","advice","cage","absurd","amount","doctor","acoustic","avoid","letter","advice","cage","absurd","amount","doctor","acoustic","avoid","letter","always"},
    ByteData("107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65")
  },
  {
    ByteData("ffffffffffffffffffffffffffffffffffffffffffffffff"),
    {"zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","when"},
    ByteData("0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528")
  },
  {
    ByteData("0000000000000000000000000000000000000000000000000000000000000000"),
    {"abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","abandon","art"},
    ByteData("bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8")
  },
  {
    ByteData("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"),
    {"legal","winner","thank","year","wave","sausage","worth","useful","legal","winner","thank","year","wave","sausage","worth","useful","legal","winner","thank","year","wave","sausage","worth","title"},
    ByteData("bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87")
  },
  {
    ByteData("8080808080808080808080808080808080808080808080808080808080808080"),
    {"letter","advice","cage","absurd","amount","doctor","acoustic","avoid","letter","advice","cage","absurd","amount","doctor","acoustic","avoid","letter","advice","cage","absurd","amount","doctor","acoustic","bless"},
    ByteData("c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f")
  },
  {
    ByteData("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    {"zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","zoo","vote"},
    ByteData("dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad")
  },
  {
    ByteData("9e885d952ad362caeb4efe34a8e91bd2"),
    {"ozone","drill","grab","fiber","curtain","grace","pudding","thank","cruise","elder","eight","picnic"},
    ByteData("274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028")
  },
  {
    ByteData("6610b25967cdcca9d59875f5cb50b0ea75433311869e930b"),
    {"gravity","machine","north","sort","system","female","filter","attitude","volume","fold","club","stay","feature","office","ecology","stable","narrow","fog"},
    ByteData("628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac")
  },
  {
    ByteData("68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c"),
    {"hamster","diagram","private","dutch","cause","delay","private","meat","slide","toddler","razor","book","happy","fancy","gospel","tennis","maple","dilemma","loan","word","shrug","inflict","delay","length"},
    ByteData("64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440")
  },
  {
    ByteData("c0ba5a8e914111210f2bd131f3d5e08d"),
    {"scheme","spot","photo","card","baby","mountain","device","kick","cradle","pact","join","borrow"},
    ByteData("ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612")
  },
  {
    ByteData("6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3"),
    {"horn","tenant","knee","talent","sponsor","spell","gate","clip","pulse","soap","slush","warm","silver","nephew","swap","uncle","crack","brave"},
    ByteData("fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d")
  },
  {
    ByteData("9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863"),
    {"panda","eyebrow","bullet","gorilla","call","smoke","muffin","taste","mesh","discover","soft","ostrich","alcohol","speed","nation","flash","devote","level","hobby","quick","inner","drive","ghost","inside"},
    ByteData("72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d")
  },
  {
    ByteData("23db8160a31d3e0dca3688ed941adbf3"),
    {"cat","swing","flag","economy","stadium","alone","churn","speed","unique","patch","report","train"},
    ByteData("deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5")
  },
  {
    ByteData("8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0"),
    {"light","rule","cinnamon","wrap","drastic","word","pride","squirrel","upgrade","then","income","fatal","apart","sustain","crack","supply","proud","access"},
    ByteData("4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02")
  },
  {
    ByteData("066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad"),
    {"all","hour","make","first","leader","extend","hole","alien","behind","guard","gospel","lava","path","output","census","museum","junior","mass","reopen","famous","sing","advance","salt","reform"},
    ByteData("26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d")
  },
  {
    ByteData("f30f8c1da665478f49b001d94c5fc452"),
    {"vessel","ladder","alter","error","federal","sibling","chat","ability","sun","glass","valve","picture"},
    ByteData("2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f")
  },
  {
    ByteData("c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05"),
    {"scissors","invite","lock","maple","supreme","raw","rapid","void","congress","muscle","digital","elegant","little","brisk","hair","mango","congress","clump"},
    ByteData("7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88")
  },
  {
    ByteData("f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f"),
    {"void","come","effort","suffer","camp","survey","warrior","heavy","shoot","primary","clutch","crush","open","amazing","screen","patrol","group","space","point","ten","exist","slush","involve","unfold"},
    ByteData("01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998")
  }
};

TEST(HDWallet, ConvertTest) {
  ByteData actual_entropy;
  std::vector<std::string> actual_mnemonic;
  ByteData actual_seed;
  bool actual_is_valid;
  HDWallet hd_wallet;

  HDWallet copy_wallet;
  ByteData copy_seed;
  for (Bip39TestVector test_vector : bip39_test_vectors) {
    EXPECT_NO_THROW(hd_wallet = HDWallet(test_vector.mnemonic, test_passphrase));
    EXPECT_NO_THROW(actual_seed = hd_wallet.GetSeed());
    EXPECT_NO_THROW(actual_entropy = HDWallet::ConvertMnemonicToEntropy(test_vector.mnemonic, language));
    EXPECT_NO_THROW(actual_mnemonic = HDWallet::ConvertEntropyToMnemonic(test_vector.entropy, language));
    EXPECT_NO_THROW(actual_is_valid = HDWallet::CheckValidMnemonic(test_vector.mnemonic, language));
    EXPECT_TRUE(actual_entropy.Equals(test_vector.entropy));
    EXPECT_EQ(actual_mnemonic, test_vector.mnemonic);
    EXPECT_TRUE(actual_seed.Equals(test_vector.seed));
    EXPECT_TRUE(actual_is_valid);

    copy_wallet = HDWallet(actual_seed);
    EXPECT_NO_THROW(copy_seed = copy_wallet.GetSeed());
    EXPECT_TRUE(copy_seed.Equals(test_vector.seed));
  }
}

const std::vector<std::string> empty_mnemonic = {};
const std::vector<std::string> invalid_words_mnemonic = {"aa","aa","aa","aa","aa","aa","aa","aa","aa","aa","aa","abort"};

TEST(HDWallet, AllowAnyMnemonicTest) {
  try {
    HDWallet hd_wallet;
    ByteData actual_seed;
    // check empty mnemonic
    EXPECT_NO_THROW(hd_wallet = HDWallet(empty_mnemonic, test_passphrase));
    EXPECT_NO_THROW(actual_seed = hd_wallet.GetSeed());

    // check invalid mnemonic
    EXPECT_NO_THROW(hd_wallet = HDWallet(invalid_words_mnemonic, test_passphrase));
    EXPECT_NO_THROW(actual_seed = hd_wallet.GetSeed());
  } catch (...) {
    // force to fail test
    EXPECT_TRUE(false);
  }
}

TEST(HDWallet, ConvertEntropyToMnemonicErrorTest) {
  std::vector<std::string> actual_mnemonic;
  try {
    ByteData empty_entropy("");
    // check empty mnemonic
    EXPECT_THROW(actual_mnemonic = HDWallet::ConvertEntropyToMnemonic(empty_entropy, language), CfdException);

    // check invalid mnemonic
    ByteData invalid_length_entropy("000000000000000000000000000000");
    EXPECT_THROW(actual_mnemonic = HDWallet::ConvertEntropyToMnemonic(invalid_length_entropy, language), CfdException);
  } catch (CfdException &e) {
    EXPECT_STREQ(e.what(), "Convert entropy to mnemonic error.");
  } catch (...) {
    // force to fail test
    EXPECT_TRUE(false);
  }

  try {
    ByteData entropy = bip39_test_vectors[0].entropy;
    EXPECT_THROW(actual_mnemonic = HDWallet::ConvertEntropyToMnemonic(entropy, "zz"), CfdException);
  } catch (CfdException &e) {
    EXPECT_STREQ(e.what(), "Not support language passed.");
  } catch (...) {
    // force to fail test
    EXPECT_TRUE(false);
  }
}

TEST(HDWallet, ConvertMnemonicToEntropyErrorTest) {
  ByteData actual_entropy;
  try {
    // check empty mnemonic
    EXPECT_THROW(actual_entropy = HDWallet::ConvertMnemonicToEntropy(empty_mnemonic, language), CfdException);

    // check invalid mnemonic
    EXPECT_THROW(actual_entropy = HDWallet::ConvertMnemonicToEntropy(invalid_words_mnemonic, language), CfdException);
  } catch (CfdException &e) {
    EXPECT_STREQ(e.what(), "Convert mnemonic to entropy error.");
  } catch (...) {
    // force to fail test
    EXPECT_TRUE(false);
  }

  try {
    std::vector<std::string> mnemonic = bip39_test_vectors[0].mnemonic;
    EXPECT_THROW(actual_entropy = HDWallet::ConvertMnemonicToEntropy(mnemonic, "zz"), CfdException);
  } catch (CfdException &e) {
    EXPECT_STREQ(e.what(), "Not support language passed.");
  } catch (...) {
    // force to fail test
    EXPECT_TRUE(false);
  }
}

TEST(HDWallet, CheckInvalidMnemonicTest) {
  // check empty mnemonic
  EXPECT_FALSE(HDWallet::CheckValidMnemonic(empty_mnemonic, language));

  // check invalid mnemonic
  EXPECT_FALSE(HDWallet::CheckValidMnemonic(invalid_words_mnemonic, language));

  try {
    EXPECT_THROW(HDWallet::CheckValidMnemonic(bip39_test_vectors[0].mnemonic, "zz"), CfdException);
  } catch (CfdException &e) {
    EXPECT_STREQ(e.what(), "Not support language passed.");
  } catch (...) {
    // force to fail test
    EXPECT_TRUE(false);
  }
}

TEST(HDWallet, GeneratePrivkeyTest) {
  ByteData seed("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");

  HDWallet wallet;
  EXPECT_NO_THROW((wallet = HDWallet(seed)));

  ExtPrivkey privkey;
  EXPECT_NO_THROW((privkey = wallet.GeneratePrivkey(NetType::kMainnet)));
  EXPECT_STREQ(privkey.ToString().c_str(), "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF");

  EXPECT_NO_THROW((privkey = wallet.GeneratePrivkey(NetType::kTestnet)));
  EXPECT_STREQ(privkey.ToString().c_str(), "tprv8ZgxMBicQKsPeWHBt7a68nPnvgTnuDhUgDWC8wZCgA8GahrQ3f3uWpq7wE7Uc1dLBnCe1hhCZ886K6ND37memRDWqsA9HgSKDXtwh2Qxo6J");

  std::vector<uint32_t> path = {0, 44};
  ExtPrivkey privkey0;
  EXPECT_NO_THROW((privkey0 = wallet.GeneratePrivkey(NetType::kMainnet, path)));
  EXPECT_STREQ(privkey0.ToString().c_str(), "xprv9wiYQ21HNxnQ8FxBjbYjJy5ckuEZ6CAFsKdHEnfkRcw5pZbXAFSturoZugNE6ZpVSu6kdrYw752chFPAbPMXZ62ZLfYwLMHdzMVXqwnfRFn");

  ExtPrivkey privkey1;
  EXPECT_NO_THROW((privkey1 = wallet.GeneratePrivkey(NetType::kMainnet, 0)));
  EXPECT_STREQ(privkey1.ToString().c_str(), "xprv9vEG8CuCbvqnJXhr1ZTHZYJcYqGMZ8dkphAUT2CDZsfqewNpq42oSiFgBXXYwDWAHXVbHew4uBfiHNAahRGJ8kUWwqwTGSXUb4wrbWz9eqo");
  ExtPrivkey privkey2;
  EXPECT_NO_THROW((privkey2 = privkey1.DerivePrivkey(44)));
  EXPECT_STREQ(privkey2.ToString().c_str(), privkey0.ToString().c_str());

  ExtPrivkey privkeyh;
  EXPECT_NO_THROW((privkeyh = wallet.GeneratePrivkey(NetType::kMainnet, "m/0h/44h")));
  EXPECT_STREQ(privkeyh.ToString().c_str(), "xprv9xcgxExFiq8qWLdxFHXpEZF8VH7Qr9YDZb8c7vMsqygWk2YGTBgSnDtm1LESskfAJqGMWkWWGagNCSbHdVgA8EFxSbfAQTKSD1z4iJ8qHtq");

  KeyData keypath1;
  EXPECT_NO_THROW((keypath1 = wallet.GeneratePrivkeyData(NetType::kMainnet, "m/0h/44h")));
  EXPECT_STREQ(keypath1.ToString().c_str(), "[b4e3f5ed/0'/44']035d3d3ee3ce7044686e0eb4697d92478658ac9f854c3c2bccd7a5a8aa74d3fc7a");
  EXPECT_STREQ(keypath1.ToString(false).c_str(), "[b4e3f5ed/0'/44']xprv9xcgxExFiq8qWLdxFHXpEZF8VH7Qr9YDZb8c7vMsqygWk2YGTBgSnDtm1LESskfAJqGMWkWWGagNCSbHdVgA8EFxSbfAQTKSD1z4iJ8qHtq");
  
  std::vector<uint32_t> path2 = {0x80000000, 0x80000000 + 44};
  KeyData keypath2;
  EXPECT_NO_THROW((keypath2 = wallet.GeneratePrivkeyData(NetType::kMainnet, path2)));
  EXPECT_STREQ(keypath2.ToString(false).c_str(), "[b4e3f5ed/0'/44']xprv9xcgxExFiq8qWLdxFHXpEZF8VH7Qr9YDZb8c7vMsqygWk2YGTBgSnDtm1LESskfAJqGMWkWWGagNCSbHdVgA8EFxSbfAQTKSD1z4iJ8qHtq");
}

TEST(HDWallet, GeneratePubkeyTest) {
  ByteData seed("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");

  HDWallet wallet;
  EXPECT_NO_THROW((wallet = HDWallet(seed)));

  ExtPubkey pubkey;
  EXPECT_NO_THROW((pubkey = wallet.GeneratePubkey(NetType::kMainnet)));
  EXPECT_STREQ(pubkey.ToString().c_str(), "xpub661MyMwAqRbcGB88KaFbLGiYAat55APKhtWg4uYMkXAmfuSTbq2QYsn9sKJCj1YqZPafsboef4h4YbXXhNhPwMbkHTpkf3zLhx7HvFw1NDy");

  EXPECT_NO_THROW((pubkey = wallet.GeneratePubkey(NetType::kTestnet)));
  EXPECT_STREQ(pubkey.ToString().c_str(), "tpubD6NzVbkrYhZ4XyJymmEgYC3uVhyj4YtPFX6yRTbW6RvfRC7Ag3sVhKSz7MNzFWW5MJ7aVBKXCAX7En296EYdpo43M4a4LaeaHuhhgHToSJF");

  std::vector<uint32_t> path = {0, 44};
  ExtPubkey pubkey0;
  EXPECT_NO_THROW((pubkey0 = wallet.GeneratePubkey(NetType::kMainnet, path)));
  EXPECT_STREQ(pubkey0.ToString().c_str(), "xpub6AhtoXYBDLLhLk2eqd5jg72MJw53Vet7EYYt3B5MyxU4hMvfhnm9Tf83kwN1aV5j6g9smszDdCg8dt4uguGHivB75PvNxPkdmecoAqqn7Hm");

  ExtPubkey pubkey1;
  EXPECT_NO_THROW((pubkey1 = wallet.GeneratePubkey(NetType::kMainnet, 0)));
  EXPECT_STREQ(pubkey1.ToString().c_str(), "xpub69DcXiS6SJQ5X1nK7azHvgFM6s6qxbMcBv65FQbq8DCpXjhyNbM3zWaA2p4L7Na2siUqFvyuK9W11J6GjqQhtPeJkeadtSpFcf6XLdKsZLZ");
  ExtPubkey pubkey2;
  EXPECT_NO_THROW((pubkey2 = pubkey1.DerivePubkey(44)));
  EXPECT_STREQ(pubkey2.ToString().c_str(), pubkey0.ToString().c_str());

  ExtPubkey pubkeyh;
  EXPECT_NO_THROW((pubkeyh = wallet.GeneratePubkey(NetType::kMainnet, "m/0H/44H")));
  EXPECT_STREQ(pubkeyh.ToString().c_str(), "xpub6Bc3MkV9ZCh8ipiRMK4pbhBs3JwuFcG4vp4CvJmVQKDVcpsQzizhL2DErc5DHMQuKwBxTg1jLP6PCqriLmLsJzjB2kD9TE9hvqxQ4yLKtcV");
  
  KeyData keypath1;
  EXPECT_NO_THROW((keypath1 = wallet.GeneratePubkeyData(NetType::kMainnet, "m/0H/44H")));
  EXPECT_STREQ(keypath1.ToString().c_str(), "[b4e3f5ed/0'/44']035d3d3ee3ce7044686e0eb4697d92478658ac9f854c3c2bccd7a5a8aa74d3fc7a");
  EXPECT_STREQ(keypath1.ToString(false).c_str(), "[b4e3f5ed/0'/44']xpub6Bc3MkV9ZCh8ipiRMK4pbhBs3JwuFcG4vp4CvJmVQKDVcpsQzizhL2DErc5DHMQuKwBxTg1jLP6PCqriLmLsJzjB2kD9TE9hvqxQ4yLKtcV");

  std::vector<uint32_t> path2 = {0x80000000, 0x80000000 + 44};
  KeyData keypath2;
  EXPECT_NO_THROW((keypath2 = wallet.GeneratePubkeyData(NetType::kMainnet, path2)));
  EXPECT_STREQ(keypath2.ToString(false).c_str(), "[b4e3f5ed/0'/44']xpub6Bc3MkV9ZCh8ipiRMK4pbhBs3JwuFcG4vp4CvJmVQKDVcpsQzizhL2DErc5DHMQuKwBxTg1jLP6PCqriLmLsJzjB2kD9TE9hvqxQ4yLKtcV");
}
