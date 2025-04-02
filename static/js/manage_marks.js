document.addEventListener('DOMContentLoaded', function () {
    const studentSelect = document.getElementById('student-select');
    const gradeSection = document.getElementById('grade-section');
    const flashBox = document.getElementById('flash-message');

    // Show flash message then hide
    function showFlashMessage(message) {
        if (!flashBox) return;
        flashBox.textContent = message;
        flashBox.style.display = 'block';

        setTimeout(() => {
            flashBox.style.display = 'none';
            flashBox.textContent = '';
        }, 3000);
    }

    if (studentSelect) {
        studentSelect.addEventListener('change', function () {
            const studentId = this.value;
            if (!studentId) return;

            fetch('/manage_marks', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ student_id: studentId })
            })
            .then(res => res.json())
            .then(data => {
                if (data.html) gradeSection.innerHTML = data.html;
                if (data.message) showFlashMessage(data.message);
            })
            .catch(err => console.error('Error fetching grades:', err));
        });
    }

    document.body.addEventListener('submit', function (e) {
        if (e.target && e.target.id === 'grade-form') {
            e.preventDefault();
            const form = e.target;

            fetch('/manage_marks', {
                method: 'POST',
                body: new FormData(form)
            })
            .then(res => res.json())
            .then(data => {
                if (data.html) gradeSection.innerHTML = data.html;
                if (data.message) showFlashMessage(data.message);
            })
            .catch(err => console.error('Error saving grade:', err));
        }
    });
});
