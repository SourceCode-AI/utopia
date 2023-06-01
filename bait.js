

var bait_remove_nodes = function(){
    var remove_elems = [
        ".tb-login__environment",
        ".tb-app-header__environment"
    ];

    remove_elems.forEach((q) => {
        document.querySelectorAll(q).forEach((elem) => {
            elem.remove();
        });
    });
};

var bait_replace_text = function(event){
    var elem = event.target;
    /*if (!!elem.innerHTML){
       elem.innerHTML = elem.innerHTML.replace("Meno Drzitela", "RAtatata");
    }*/
};

document.addEventListener("DOMContentLoaded", bait_remove_nodes);
document.addEventListener("DOMNodeInserted", bait_remove_nodes);
document.addEventListener("DOMNodeInserted", bait_replace_text);
