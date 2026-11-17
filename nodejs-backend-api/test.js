fetch('http://localhost:5000/api/polls/1/results')
.then(response => response.json())
.then(data => console.log('Live Poll Results:', data))
.catch(error => console.error('Error:', error));