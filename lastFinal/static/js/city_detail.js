function initMap() {
  const cityLat = parseFloat('{{ city.latitude }}');
  const cityLng = parseFloat('{{ city.longitude }}');

  const mapOptions = {
      center: { lat: cityLat, lng: cityLng },
      zoom: 12,
  };

  const map = new google.maps.Map(document.getElementById('map'), mapOptions);

  const marker = new google.maps.Marker({
      position: { lat: cityLat, lng: cityLng },
      map: map,
      title: '{{ city.city_name }}'
  });

  document.addEventListener('DOMContentLoaded', function() {
    const showRouteButton = document.getElementById('showRouteButton');
  
    showRouteButton.addEventListener('click', function() {
      // Kullanıcıya konum izni iste
      if (navigator.geolocation) {
        navigator.geolocation.getCurrentPosition(function(position) {
          const yourLat = position.coords.latitude;
          const yourLng = position.coords.longitude;
          
          // Rota çizme işlemi
          const directionsService = new google.maps.DirectionsService();
          const directionsRenderer = new google.maps.DirectionsRenderer();
          directionsRenderer.setMap(map);
          
          const request = {
              origin: { lat: yourLat, lng: yourLng }, // Başlangıç noktası
              destination: { lat: cityLat, lng: cityLng }, // Hedef noktası
              travelMode: 'DRIVING' // Seyahat modu (Örneğin: DRIVING, WALKING, BICYCLING)
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
        window.alert('Tarayıcınız konum bilgisini desteklemiyor.');
      }
    });
  });
  
}
