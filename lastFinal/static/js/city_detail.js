function initMap() {
  const cityLat = parseFloat('{{ city.latitude }}');
  const cityLng = parseFloat('{{ city.longitude }}');

  const mapOptions = {
    center: { lat: cityLat, lng: cityLng },
    zoom: 12,
  };

  const mapElement = document.getElementById('map');
  
  if (!mapElement) {
    console.error("Map element not found.");
    return;
  }

  const map = new google.maps.Map(mapElement, mapOptions);

  const marker = new google.maps.Marker({
    position: { lat: cityLat, lng: cityLng },
    map: map,
    title: '{{ city.city_name }}'
  });

  document.addEventListener('DOMContentLoaded', function() {
    const showRouteButton = document.getElementById('showRouteButton');
  
    showRouteButton.addEventListener('click', function() {
      if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function(position) {
          const yourLat = position.coords.latitude;
          const yourLng = position.coords.longitude;
          
          const directionsService = new google.maps.DirectionsService();
          const directionsRenderer = new google.maps.DirectionsRenderer();
          directionsRenderer.setMap(map);
          
          const request = {
              origin: { lat: yourLat, lng: yourLng },
              destination: { lat: cityLat, lng: cityLng },
              travelMode: 'DRIVING'
          };
  
          directionsService.route(request, function(response, status) {
              if (status === 'OK') {
                  directionsRenderer.setDirections(response);
              } else {
                  window.alert('Directions request failed due to ' + status);
              }
          });
        });
      } else {
        window.alert('Your browser does not support geolocation.');
      }
    });
  });
}

initMap();