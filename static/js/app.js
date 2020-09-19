$(function() {

	$('a#device-submit').bind('click', function() {

		$.getJSON('/device_scan', {

			gateway_ip: $('input[name="default-gateway"]').val(),

			

		}, function(data) {

			$.each(data, function(index, value) {
				
				for(i = 0; i < value.length; i++) {

					var $elem = $('tbody.device-section');

					$elem.append(
						$('<tr/>').append(
							$('<td/>', {text: value[i].IP_address})
						).append(
							$('<td/>', {text: value[i].Manufacturer})
						).append(
							$('<td/>', {text: value[i].MAC_address})
						).append(
							$('<td/>', {text: value[i].OS_details})
									

								

							
								
						)

					)

				};

			});

		});
		return false;


	});


});


