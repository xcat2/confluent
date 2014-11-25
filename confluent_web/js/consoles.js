function getRequest(url, success) {
    var request = new XMLHttpRequest();
    request.open('GET', url, true);
    request.setRequestHeader('Accept', 'application/json');
    request.onload = function() {
        if (this.status >= 200 && this.status <= 400) {
            success(JSON.parse(this.responseText));
        }
    };
    request.send();
}

document.addEventListener('DOMContentLoaded', function() {

  getRequest("/confluent-api/nodes/", function( data) {
	var items = [];
	var options = [];
	var nodename = "";
    data["_links"]["item"].forEach( function( val, key ) {
        console.log(val);
        if (typeof(val) == "object") {
		    nodename = val.href;
        } else {
            nodename = val;
        }
        console.log(nodename);
		nodename = nodename.replace('/', '');
        var myrow = document.createElement('div');
        myrow.innerHTML = "<button id="+nodename+">"+nodename+"</button><br>";
        document.getElementById("nodes").appendChild(myrow);
        document.getElementById(nodename).addEventListener("click", function( event ) {
            var tname = this.id;
            var url  = "/confluent-api/nodes/" + tname + "/console/session";
            new ConsoleWindow(url, tname);
        });
	});
  });
}); // end document
