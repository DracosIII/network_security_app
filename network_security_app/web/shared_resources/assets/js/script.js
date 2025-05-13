// Change navbar background on scroll
window.addEventListener('scroll', () => {
  const navbar = document.querySelector('.navbar');
  if (window.scrollY > 50) {
    navbar.classList.add('scrolled');
  } else {
    navbar.classList.remove('scrolled');
  }
});

// Dynamic typing effect
const text = "Welcome to My Sniffy";
let index = 0;

function typeText() {
  const dynamicText = document.querySelector('.dynamic-text');
  if (dynamicText) {
    if (index < text.length) {
      dynamicText.textContent += text.charAt(index);
      index++;
      setTimeout(typeText, 100);
    }
  }
}

typeText();

document.querySelector('.toggle-dark-mode').addEventListener('click', () => {
  document.body.classList.toggle('dark-mode');
});

const slider = document.querySelector('.testimonial-slider');
let currentIndex = 0;

setInterval(() => {
  currentIndex = (currentIndex + 1) % slider.children.length;
  slider.style.transform = `translateX(-${currentIndex * 100}%)`;
}, 3000);

const map = document.getElementById('map');

// Simulation d'appareils sur la carte
const devices = [
  { x: 50, y: 50, name: 'Device 1' },
  { x: 150, y: 120, name: 'Device 2' },
];

devices.forEach(device => {
  const point = document.createElement('div');
  point.style.position = 'absolute';
  point.style.left = `${device.x}px`;
  point.style.top = `${device.y}px`;
  point.style.width = '10px';
  point.style.height = '10px';
  point.style.background = 'red';
  point.title = device.name;
  map.appendChild(point);
});
console.log("Le script.js est bien relié !");

let password = ""
let 
const getUser = () => {

  // exemple de fonction login 
  const user = fetch("https://login.com", {
    method: "POST",
    body: {
      "login": `${login}`,
      "password": `${password}`
    }

  });

  // recupérer la réponse
  return user;
};


document.getElementById('login-form').addEventListener('submit', function(event) {
  event.preventDefault();
  const username = document.getElementById('login-username').value;
  const password = document.getElementById('login-password').value;

  fetch('/login', {
      method: 'POST',
      body: new URLSearchParams({
          'username': username,
          'password': password
      }),
      headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
      },
  })
  .then(response => response.json())
  .then(data => {
      if (data.success) {
          window.location.href = '/dashboard';  // Redirect to a dashboard or a success page
      } else {
          alert(data.message);  // Show error message
      }
  })
  .catch(error => console.error('Error:', error));
});
