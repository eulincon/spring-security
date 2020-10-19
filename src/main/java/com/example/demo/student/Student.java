package com.example.demo.student;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter @Setter
@AllArgsConstructor
@NoArgsConstructor
public class Student {
	private final Integer studentId;
	private final String studentName;
	
	
	public Student(Integer studentId, String studentName) {
		super();
		this.studentId = studentId;
		this.studentName = studentName;
	}
	public Integer getStudentId() {
		return studentId;
	}
	public String getStudentName() {
		return studentName;
	}
	
	
}
