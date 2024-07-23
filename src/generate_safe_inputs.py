import random
import string
import os
import calendar

first_names = [
    "John", "Jane", "Michael", "Sarah", "David", "Emily", "Robert", "Linda", "James", "Patricia", "Christopher", "Barbara",
    "Daniel", "Elizabeth", "Matthew", "Jennifer", "Joshua", "Maria", "Andrew", "Jessica", "William", "Susan", "Joseph", "Karen",
    "Kevin", "Nancy", "Brian", "Margaret", "Edward", "Sandra", "Thomas", "Ashley", "Richard", "Kimberly", "Anthony", "Lisa",
    "Mark", "Donna", "Charles", "Carol", "Paul", "Michelle", "Steven", "Deborah", "Kenneth", "Dorothy", "George", "Betty",
    "Eric", "Helen", "Jonathan", "Linda", "Scott", "Kathleen", "Larry", "Amy", "Jeffrey", "Sharon", "Frank", "Anna",
    "Raymond", "Cynthia", "Gregory", "Angela", "Jacob", "Debra", "Stephen", "Laura", "Justin", "Marie", "Dennis", "Julie",
    "Walter", "Christine", "Patrick", "Kelly", "Peter", "Victoria", "Jerry", "Martha", "Harold", "Judith", "Keith", "Cheryl",
    "Albert", "Megan", "Roger", "Andrea", "Bruce", "Diane", "Jeremy", "Janet", "Carl", "Catherine", "Henry", "Carolyn",
    "Arthur", "Rachel", "Ryan", "Heather", "Joe", "Diana", "Jack", "Katherine", "Gary", "Pamela", "Nicholas", "Virginia",
    "Ralph", "Maria", "Lawrence", "Judy", "Russell", "Grace", "Roy", "Theresa", "Benjamin", "Ruth", "Adam", "Jacqueline",
    "Wayne", "Sara", "Juan", "Hannah", "Louis", "Sylvia", "Bruce", "Evelyn", "Philip", "Joyce", "Bobby", "Gloria", "Howard", "Denise",
    "Gabriel", "Alice", "Vincent", "Anne", "Randy", "Jean", "Alexander", "Carmen", "Ernest", "Victoria", "Eugene", "Frances",
    "Billy", "Ann", "Bruce", "Grace", "Joe", "Amber", "Bryan", "Shirley", "Terry", "Rose", "Jordan", "Beverly", "Sean", "Madison",
    "Walter", "Danielle", "Samuel", "Theresa", "Jesse", "Joan", "Austin", "Marilyn", "Christian", "Charlotte", "Dylan", "Lori",
    "Ethan", "Courtney", "Zachary", "Marilyn", "Austin", "Sophia", "Tyler", "Alexis", "Logan", "Kathy", "Caleb", "Crystal",
    "Lucas", "Holly", "Hunter", "Clara", "Isaac", "Kristen", "Chase", "Alyssa", "Gavin", "Kelsey", "Cameron", "Tina"
]

last_names = [
    "Smith", "Johnson", "Brown", "Williams", "Jones", "Miller", "Davis", "Garcia", "Rodriguez", "Martinez", "Hernandez", "Lopez",
    "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
    "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King", "Wright", "Scott",
    "Torres", "Nguyen", "Hill", "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker", "Cruz", "Edwards", "Collins", "Reyes",
    "Stewart", "Morris", "Morales", "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey",
    "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson", "Watson", "Brooks", "Chavez", "Wood", "James",
    "Bennett", "Gray", "Mendoza", "Ruiz", "Hughes", "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers", "Long",
    "Ross", "Foster", "Jimenez", "Powell", "Jenkins", "Perry", "Russell", "Sullivan", "Bell", "Coleman", "Butler", "Henderson",
    "Barnes", "Gonzales", "Fisher", "Vasquez", "Simmons", "Romero", "Jordan", "Patterson", "Alexander", "Hamilton", "Graham",
    "Reynolds", "Griffin", "Wallace", "Moreno", "West", "Cole", "Hayes", "Bryant", "Herrera", "Gibson", "Ellis", "Tran",
    "Medina", "Aguilar", "Stevens", "Murray", "Ford", "Castro", "Marshall", "Owens", "Harrison", "Fernandez", "McDonald",
    "Woods", "Washington", "Kennedy", "Wells", "Vargas", "Henry", "Chen", "Freeman", "Webb", "Tucker", "Guzman", "Burns",
    "Crawford", "Olson", "Simpson", "Porter", "Hunter", "Gordon", "Mendez", "Silva", "Shaw", "Snyder", "Mason", "Dixon",
    "Munoz", "Hunt", "Hicks", "Holmes", "Palmer", "Wagner", "Black", "Robertson", "Boyd", "Rose", "Stone", "Salazar",
    "Fox", "Warren", "Mills", "Meyer", "Rice", "Schmidt", "Garza", "Daniels", "Ferguson", "Nichols", "Stephens", "Soto",
    "Weaver", "Ryan", "Gardner", "Payne", "Grant", "Dunn", "Kelley", "Spencer", "Hawkins", "Arnold", "Pierce", "Vazquez",
    "Hansen", "Peters", "Santos", "Hart", "Bradley", "Knight", "Elliott", "Cunningham", "Duncan", "Armstrong", "Hudson",
    "Carroll", "Lane", "Riley", "Andrews", "Alvarado", "Ray", "Delgado", "Berry", "Perkins", "Hoffman", "Johnston",
    "Matthews", "Pena", "Richards", "Contreras", "Willis", "Carpenter", "Lawrence", "Sandoval", "Guerrero", "George",
    "Chapman", "Rios", "Estrada", "Ortega", "Watkins", "Greene", "Nunez", "Wheeler", "Valdez", "Harper", "Burke", "Larson",
    "Soto", "Duncan", "Armstrong", "Hudson", "Lane", "Riley", "Andrews", "George", "Chapman", "Rios", "Estrada", "Ortega",
    "Harper", "Burke", "Larson", "Soto"
]

domains = ["example.com", "email.com", "mail.com", "webmail.com", "service.com", "domain.com", "provider.com", "site.com", "internet.com", 
           "website.com", "fastmail.com", "protonmail.com", "outlook.com", "yahoo.com", "gmail.com", "icloud.com", "zoho.com", "yandex.com", 
           "gmx.com", "mail.ru", "inbox.com", "aol.com", "hotmail.com", "live.com", "msn.com", "rediffmail.com", "hushmail.com", "tutanota.com", "runbox.com", "posteo.de"]

streets = [
    "Main St", "High St", "Broadway", "Market St", "Oak St", "Pine St", "Maple St", "Cedar St", "Elm St", "Washington St",
    "Lake St", "Hill St", "Church St", "Center St", "Park St", "South St", "North St", "River St", "Union St", "West St",
    "East St", "Spruce St", "Cherry St", "Chestnut St", "Willow St", "Beech St", "Walnut St", "Birch St", "Sycamore St",
    "Hickory St", "Ash St", "Magnolia St", "Fir St", "Holly St", "Linden St", "Aspen St", "Alder St", "Maple Ave", "Oak Ave",
    "Pine Ave", "Elm Ave", "Cedar Ave", "Spruce Ave", "Cherry Ave", "Chestnut Ave", "Willow Ave", "Beech Ave", "Walnut Ave",
    "Birch Ave", "Sycamore Ave", "Hickory Ave", "Ash Ave", "Magnolia Ave", "Fir Ave", "Holly Ave", "Linden Ave", "Aspen Ave",
    "Alder Ave", "Maple Dr", "Oak Dr", "Pine Dr", "Elm Dr", "Cedar Dr", "Spruce Dr", "Cherry Dr", "Chestnut Dr", "Willow Dr",
    "Beech Dr", "Walnut Dr", "Birch Dr", "Sycamore Dr", "Hickory Dr", "Ash Dr", "Magnolia Dr", "Fir Dr", "Holly Dr", "Linden Dr",
    "Aspen Dr", "Alder Dr", "Maple Blvd", "Oak Blvd", "Pine Blvd", "Elm Blvd", "Cedar Blvd", "Spruce Blvd", "Cherry Blvd",
    "Chestnut Blvd", "Willow Blvd", "Beech Blvd", "Walnut Blvd", "Birch Blvd", "Sycamore Blvd", "Hickory Blvd", "Ash Blvd",
    "Magnolia Blvd", "Fir Blvd", "Holly Blvd", "Linden Blvd", "Aspen Blvd", "Alder Blvd", "Main Ave", "High Ave", "Broadway Ave",
    "Market Ave", "Oak Ave", "Pine Ave", "Maple Ave", "Cedar Ave", "Elm Ave", "Washington Ave", "Lake Ave", "Hill Ave",
    "Church Ave", "Center Ave", "Park Ave", "South Ave", "North Ave", "River Ave", "Union Ave", "West Ave", "East Ave",
    "Spruce Ave", "Cherry Ave", "Chestnut Ave", "Willow Ave", "Beech Ave", "Walnut Ave", "Birch Ave", "Sycamore Ave",
    "Hickory Ave", "Ash Ave", "Magnolia Ave", "Fir Ave", "Holly Ave", "Linden Ave", "Aspen Ave", "Alder Ave"
]

cities = [
    "New York, NY", "Los Angeles, CA", "Chicago, IL", "Houston, TX", "Phoenix, AZ",
    "Philadelphia, PA", "San Antonio, TX", "San Diego, CA", "Dallas, TX", "San Jose, CA",
    "Austin, TX", "Jacksonville, FL", "San Francisco, CA", "Columbus, OH", "Indianapolis, IN",
    "Fort Worth, TX", "Charlotte, NC", "Seattle, WA", "Denver, CO", "El Paso, TX",
    "Detroit, MI", "Boston, MA", "Memphis, TN", "Nashville, TN", "Baltimore, MD",
    "Louisville, KY", "Milwaukee, WI", "Portland, OR", "Las Vegas, NV", "Oklahoma City, OK",
    "Albuquerque, NM", "Tucson, AZ", "Fresno, CA", "Sacramento, CA", "Kansas City, MO",
    "Mesa, AZ", "Virginia Beach, VA", "Atlanta, GA", "Colorado Springs, CO", "Omaha, NE",
    "Raleigh, NC", "Miami, FL", "Cleveland, OH", "Tulsa, OK", "Oakland, CA",
    "Minneapolis, MN", "Wichita, KS", "Arlington, TX", "Bakersfield, CA", "Tampa, FL",
    "Aurora, CO", "Anaheim, CA", "Honolulu, HI", "Santa Ana, CA", "Corpus Christi, TX",
    "Riverside, CA", "St. Louis, MO", "Lexington, KY", "Stockton, CA", "Cincinnati, OH",
    "St. Paul, MN", "Toledo, OH", "Newark, NJ", "Greensboro, NC", "Buffalo, NY",
    "Plano, TX", "Scottsdale, AZ", "Boise, ID", "Birmingham, AL", "Spokane, WA",
    "Montgomery, AL", "Modesto, CA", "Des Moines, IA", "Fayetteville, AR", "Shreveport, LA",
    "Charleston, SC", "Salem, OR", "Santa Clara, CA", "Grand Rapids, MI", "Huntsville, AL",
    "Brownsville, TX", "McAllen, TX", "Amarillo, TX", "Oxnard, CA", "Chattanooga, TN",
    "Mobile, AL", "Jackson, MS", "Eugene, OR", "Lakeland, FL", "Provo, UT"
]


products = [
    "Wireless Mouse", "14-inch Laptop", "Bluetooth Speaker", "Smartphone", "Tablet", "Headphones", "Monitor", "Keyboard",
    "Printer", "Camera", "Router", "External Hard Drive", "Flash Drive", "Memory Card", "Gaming Console", "VR Headset",
    "Smartwatch", "Fitness Tracker", "Drone", "Smart Home Assistant", "Portable Charger", "E-reader", "Smart TV", "Projector",
    "Electric Toothbrush", "Hair Dryer", "Air Purifier", "Coffee Maker", "Blender", "Microwave Oven", "Refrigerator",
    "Dishwasher", "Washing Machine", "Dryer", "Air Conditioner", "Heater", "Vacuum Cleaner", "Fan", "Lamp", "Desk",
    "Chair", "Bookshelf", "Table", "Sofa", "Bed", "Mattress", "Pillow", "Blanket", "Curtain", "Rug", "Mirror", "Picture Frame",
    "Wall Clock", "Alarm Clock", "Calculator", "Notebook", "Pen", "Pencil", "Marker", "Stapler", "Scissors", "Tape",
    "Glue", "Ruler", "Eraser", "Sharpener", "Backpack", "Briefcase", "Wallet", "Handbag", "Sunglasses", "Watch",
    "Belt", "Hat", "Scarf", "Gloves", "Umbrella", "Raincoat", "Jacket", "Coat", "Sweater", "Shirt", "T-shirt", "Pants",
    "Jeans", "Shorts", "Skirt", "Dress", "Suit", "Tie", "Socks", "Shoes", "Sneakers", "Boots", "Sandals", "Slippers",
    "Swimsuit", "Bikini", "Sunglasses", "Hat", "Scarf", "Gloves", "Umbrella", "Raincoat", "Jacket", "Coat", "Sweater",
    "Shirt", "T-shirt", "Pants", "Jeans", "Shorts", "Skirt", "Dress", "Suit", "Tie", "Socks", "Shoes", "Sneakers",
    "Boots", "Sandals", "Slippers", "Swimsuit", "Bikini", "Smart Doorbell", "Robot Vacuum", "Electric Skateboard", 
    "Portable Projector", "Noise-Cancelling Earbuds", "Wireless Charging Pad", "Smart Light Bulbs", "Ergonomic Office Chair", 
    "Standing Desk", "Electric Toothbrush", "Smart Scale", "Air Fryer", "Instant Pot", "Sous Vide Cooker", "Cold Brew Coffee Maker", 
    "Smart Thermostat", "Weighted Blanket", "Memory Foam Pillow", "Robot Lawn Mower", "Portable Power Station", "Solar Panel Charger", 
    "Dash Cam", "Car Jump Starter", "Bluetooth Car Adapter", "Tire Pressure Monitor", "Electric Wine Opener", "Smart Door Lock", "Wi-Fi Range Extender", 
    "Mesh Wi-Fi System", "Portable Photo Printer"
]

comments = [
    "Great product, fast shipping!", "Would buy again.", "Satisfied with the purchase.", "Could be better.", "Not as expected.",
    "Excellent quality!", "Very disappointed.", "Highly recommend.", "Will not buy again.", "Exactly what I needed.",
    "Poor quality.", "Amazing service!", "Terrible experience.", "Five stars!", "One star.", "Happy with the product.",
    "Not worth the price.", "Exceeded expectations.", "Arrived damaged.", "Good value for money.", "Bad customer service.",
    "Will order again.", "Not as described.", "Very happy.", "Defective item.", "Love it!", "Hate it.", "Fast delivery.",
    "Slow shipping.", "Product is okay.", "Outstanding!", "Awful.", "Very pleased.", "Unsatisfactory.", "Top-notch quality.",
    "Subpar.", "Great deal!", "Overpriced.", "Works perfectly.", "Malfunctions.", "Superb!", "Inferior.", "Happy customer.",
    "Unhappy customer.", "Perfect fit.", "Doesn't fit.", "Love the color.", "Color is different.", "Great performance.",
    "Poor performance.", "Highly efficient.", "Inefficient.", "Best purchase ever.", "Worst purchase ever.", "Great design.",
    "Ugly design.", "Easy to use.", "Complicated to use.", "Very durable.", "Not durable.", "Highly recommend!", "Do not recommend.",
    "Impressive features.", "Lacks features.", "Great battery life.", "Short battery life.", "Very comfortable.", "Uncomfortable.",
    "Stylish.", "Outdated.", "User-friendly.", "Confusing interface.", "Very portable.", "Too bulky.", "Great sound quality.",
    "Poor sound quality.", "High-quality materials.", "Cheap materials.", "Love the packaging.", "Packaging was damaged.",
    "Great for the price.", "Not worth the money.", "Very versatile.", "Limited use.", "Amazing experience.", "Terrible experience.",
    "Perfect for my needs.", "Doesn't meet my needs.", "High-quality craftsmanship.", "Low-quality craftsmanship.", "Very intuitive.",
    "Hard to figure out.", "Very reliable.", "Unreliable.", "Great customer support.", "Bad customer support.", "Very responsive.",
    "Unresponsive.", "Highly recommend this product.", "Do not recommend this product.", "Exceeded my expectations.", "Below my expectations.",
    "Will definitely buy again.", "Will not buy again.", "Best product in its category.", "Worst product in its category.", "Very innovative.",
    "Outdated technology.", "Very stylish.", "Looks cheap.", "Very comfortable.", "Uncomfortable to wear.", "Great price.", "Too expensive.",
    "Amazing quality.", "Feels flimsy.", "Very user-friendly.", "Difficult to use.", "Great battery life.", "Battery drains quickly.",
    "Very lightweight.", "Too heavy.", "Easy to set up.", "Complicated setup.", "Great sound.", "Poor sound quality.", "Very powerful.",
    "Lacks power.", "Highly recommend this brand.", "Avoid this brand.", "Love the features.", "Features are lacking.", "Shipping was faster than expected!", 
    "Product quality exceeded my expectations.", "Customer service was very helpful.", "Instructions were clear and easy to follow.", "Great value for the price.", 
    "Packaging was eco-friendly, which I appreciate.", "Product works as advertised.", "Would make a great gift.", "Impressive attention to detail.", 
    "Sturdy construction, built to last.", "Energy-efficient, saves on bills.", "Easy to clean and maintain.", "Compact design, doesn't take up much space.", 
    "Versatile, can be used for multiple purposes.", "Sleek and modern design.", "Compatible with all my devices.", "Improved my daily routine.", "Quieter than I expected.", 
    "Fits perfectly in my space.", "Colors are vibrant and true to the picture.", "Material feels premium.", "Responsive touch controls.", "Intuitive user interface.", 
    "Great for travel.", "Holds charge for a long time.", "Easy to upgrade or expand.", "Comes with all necessary accessories.", "Well-designed app with useful features.", 
    "Excellent build quality.", "Good weight, feels substantial."
]
numeric = [str(i) for i in range(-100, 1001)] 
numeric += [str(i) for i in range(1001, 10001, 100)]  # Add larger numbers
numeric += [f"{i:.2f}" for i in [random.uniform(0.01, 1000) for _ in range(100)]]  # Add decimal values
alphanumeric = [''.join(random.choices(string.ascii_uppercase + string.digits, k=8)) for _ in range(400)]

import calendar

def generate_safe_input():
    name = f"{random.choice(first_names)} {random.choice(last_names)}"
    first_name = random.choice(first_names).lower()
    last_name = random.choice(last_names).lower()
    email_variants = [
        f"{first_name}.{last_name}@{random.choice(domains)}",
        f"{first_name}_{last_name}@{random.choice(domains)}",
        f"{first_name}{last_name}@{random.choice(domains)}",
        f"{first_name}{last_name}{random.randint(10, 99)}@{random.choice(domains)}"
    ]
    email = random.choice(email_variants)
    phone = f"+1 ({random.randint(200, 999)}) {random.randint(100, 999)}-{random.randint(1000, 9999)}"
    year = random.randint(1980, 2023)
    month = random.randint(1, 12)
    day = random.randint(1, calendar.monthrange(year, month)[1])
    date = f"{year}-{month:02d}-{day:02d}"
    address = f"{random.randint(1, 9999)} {random.choice(streets)}, {random.choice(cities)} {random.randint(10000, 99999)}"
    product = random.choice(products)
    comment = random.choice(comments)
    numeric_input = random.choice(numeric)
    alphanumeric_input = random.choice(alphanumeric)

    generators = [name, email, phone, date, address, product, comment, numeric_input, alphanumeric_input]
    return random.choice(generators)


# Generate 10,000 synthetic safe inputs
safe_inputs = [generate_safe_input() for _ in range(10000)]

# Save to a file
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
with open(os.path.join(project_root, 'safe_user_inputs.txt'), 'w') as file:
    for input_str in safe_inputs:
        file.write(f"{input_str}\n")

print(f"Generated {len(safe_inputs)} safe inputs and saved to 'safe_user_inputs.txt'")